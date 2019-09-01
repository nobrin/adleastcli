#!/usr/bin/env python3
"""
ADLeastCLI is a simple user manager for Active Directory (AD) on Python.
It has simply essential functions and makes to manage users/groups on AD without joining realm.
Therefore, it fits when you want to use AD on short usage.
"""
__author__ = "Nobuo Okazaki"
__version__ = "0.0.1"
__license__ = "MIT License"

import ldap3

# --- Exceptions
class UserOperationFailed(Exception): pass

# --- Main Class
class UserManager(object):
    def __init__(self, domain, host=None):
        self.domain = domain
        self.host = host or self.domain
        self.connection = None

    @property
    def domain_dn(self):
        return ",".join(["DC={}".format(x) for x in self.domain.split(".")])

    def connect(self, username, password):
        # Connect to the server
        user = "{}@{}".format(username, self.domain)
        server = ldap3.Server(self.host, get_info=ldap3.ALL)
        self.conn = ldap3.Connection(server, user=user, password=password, check_names=True, auto_bind=True)

    def get_user_dn(self, common_name):
        # Construct User DN
        return "CN={},CN=Users,".format(common_name) + self.domain_dn

    def create_user(self, username, password=None):
        # Create User and set password (if specified)
        # Append attributes for user
        user_dn = self.get_user_dn(username)
        attr = {
            "displayName": username,
            "sAMAccountName": username,
            "userAccountControl": 512,
            "userPrincipalName": "{}@{}".format(username, self.domain.upper()),
        }
        if not self.conn.add(user_dn, ["user"], attr):
            raise UserOperationFailed(self.conn.result)

        if password is not None:
            self.set_user_password(username, password)

        return True

    def set_user_password(self, username, password):
        # Set password for user
        user_dn = self.get_user_dn(username)
        if not self.conn.extend.microsoft.modify_password(user_dn, password):
            raise UserOperationFailed(self.conn.result)
        return True

    def change_user_password(self, username, newpw, oldpw):
        # Change user password (as a general user)
        user_dn = self.get_user_dn(username)
        if not ldap3.extend.microsoft.modifyPassword.ad_modify_password(self.conn, user_dn, newpw, oldpw, controls=None):
            raise UserOperationFailed(conn.result)
        return True

    def delete_object(self, common_name):
        # Delete object(user or group)
        dn = self.get_user_dn(common_name)
        if not self.conn.delete(dn): raise UserOperationFailed(conn.result)
        return True

    def create_group(self, groupname, desc=""):
        # Create group
        grp_dn = self.get_user_dn(groupname)
        attr = {"sAMAccountName": groupname}
        if desc: attr["description"] = desc
        if not self.conn.add(grp_dn, ["group"], attr):
            raise UserOperationFailed(conn.result)
        return True

    def add_member_to_group(self, username, groupname):
        # Add user to the group
        user_dn = self.get_user_dn(username)
        grp_dn = self.get_user_dn(groupname)
        if not self.conn.extend.microsoft.add_members_to_groups(user_dn, grp_dn):
            raise UserOperationFailed(conn.result)
        return True

    def remove_member_from_group(self, username, groupname):
        # Remove user from the group
        user_dn = self.get_user_dn(username)
        grp_dn = self.get_user_dn(groupname)
        if not self.conn.extend.microsoft.remove_members_from_groups(user_dn, grp_dn):
            raise UserOperationFailed(conn.result)
        return True

    def list(self, category):
        # List users (CN=Users)
        search_base = "CN=Users," + self.domain_dn
        search_filter = "(objectCategory={})".format(category)
        self.conn.search(search_base, search_filter, attributes=ldap3.ALL_ATTRIBUTES)
        for obj in self.conn.response:
            if "attributes" not in obj: continue
            attr = obj["attributes"]
            if attr.get("isCriticalSystemObject"): continue
            print(attr["cn"])
#            print("{:20} {}".format(attr["cn"], attr.get("description", [""])[0]))

    def info(self, category, common_name):
        # Show information of specified object
        search_base = "CN=Users," + self.domain_dn
        search_filter = "(&(objectCategory={})(cn={}))".format(category, common_name)
        self.conn.search(search_base, search_filter, attributes=ldap3.ALL_ATTRIBUTES)
        info = self.conn.response[0]["attributes"]
        print("CN: {}".format(info.pop("cn")))
        for k, v in sorted(info.items()):
            print("  {:20}{}".format(k, v))

if __name__ == "__main__":
    import sys, argparse
    from getpass import getpass

    parser = argparse.ArgumentParser(description="AD Util")
    parser.add_argument("target", choices=["user", "group"])
    parser.add_argument("target_args", metavar="ARGS", type=str, nargs="*")
    parser.add_argument("-S", dest="domain", required=True)
    parser.add_argument("-U", dest="adm_user", default="Administrator")
    args = parser.parse_args()

    ADM_USER = args.adm_user
    ADM_PASS = getpass("Enter password for {}: ".format(ADM_USER))

    mgr = UserManager(args.domain)
    try:
        mgr.connect(ADM_USER, ADM_PASS)
    except Exception as e:
        sys.stderr.write("Failed connecting to server.\n  Message: {}\n".format(e))
        sys.exit(1)

    try:
        p = args.target_args
        if args.target == "user":
            if not p: mgr.list("user")
            elif p[0] == "setpw":
                mgr.set_user_password(p[1], p[2])
                sys.stderr.write("New password set.\n")
            elif p[0] == "passwd":
                oldpw = ADM_PASS
                newpw = getpass("Enter new password: ")
                newpw_confirm = getpass("Confirm new password: ")
                if newpw != newpw_confirm:
                    sys.stderr.write("New passwords does not match.\n")
                    sys.exit(1)
                mgr.change_user_password(ADM_USER, newpw, oldpw)
                sys.stderr.write("Password changed.\n")
            elif p[0] == "create":
                mgr.create_user(p[1], p[2])
                sys.stderr.write("User '{}' created.\n".format(p[1]))
            elif p[0] == "delete":
                mgr.delete_object(p[1])
                sys.stderr.write("User '{}' deleted.\n".format(p[1]))
            elif p[0] == "join":
                mgr.add_member_to_group(p[1], p[2])
                sys.stderr.write("User '{}' added to Group '{}'.\n".format(p[1], p[2]))
            elif p[0] == "leave":
                mgr.remove_member_from_group(p[1], p[2])
                sys.stderr.write("User '{}' removed from Group '{}'.\n".format(p[1], p[2]))
            elif p[0] == "info": mgr.info("user", p[1])
            else:
                sys.stderr.write("Invalid arg\n")
                sys.exit(1)
        elif args.target == "group":
            if not p: mgr.list("group")
            elif p[0] == "create":
                mgr.create_group(p[1])
                sys.stderr.write("Group '{}' has been created.\n".format(p[1]))
            elif p[0] == "delete":
                mgr.delete_object(p[1])
                sys.stderr.write("Group '{}' has been deleted.\n".format(p[1]))
            elif p[0] == "info": mgr.info("group", p[1])
            else:
                sys.stderr.write("Invalid arg\n")
                sys.exit(1)
    except UserOperationFailed as e:
        sys.stderr.write("Operation failed:\n{}\n".format(e))
        sys.exit(1)
