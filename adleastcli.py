#!/usr/bin/env python3
"""
ADLeastCLI is a simple user manager for Active Directory (AD) on Python.
It has simply essential functions and makes to manage users/groups on AD without joining realm.
Therefore, it fits when you want to use AD on short usage.
"""
__author__ = "Nobuo Okazaki"
__version__ = "0.0.2"
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
            raise UserOperationFailed(self.conn.result)
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

def start_web_server(mgr, bind_addr):
    # Start web server for changing password by oneself
    import json, re, traceback
    from http import HTTPStatus
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class NotProcessed(object): pass
    class TinyHTTPRequestHandler(BaseHTTPRequestHandler):
        # Very limited http handler
        routes = []

        @classmethod
        def route(cls, path, method):
            def wrapper(func):
                cls.routes.append((method, path, func))
            return wrapper

        def _handle_request(self, method):
            body = NotProcessed()
            response_headers = []
            for rt in self.routes:
                if rt[0] == method and rt[1] == self.path:
                    content_type, body = rt[2](self, response_headers)
                    try:
                        body = body.encode()
                    except Exception as e:
                        traceback.print_exc(e)
                        self.send_error(500, "Internal Server Error")
                        return

            if isinstance(body, NotProcessed):
                self.send_error(404, "Not Found")
                return

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            for header in response_headers:
                self.send_header(*header)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self): self._handle_request("GET")
        def do_POST(self): self._handle_request("POST")

    @TinyHTTPRequestHandler.route("/", "GET")
    def callback(handler, response_headers):
        return "text/html", HTML_FORM

    @TinyHTTPRequestHandler.route("/api/passwd", "POST")
    def callback(handler, response_headers):
        # Change user password
        # Parameter: {"acc": Account, "cur": Current Password, "npw": New Password}
        obj = json.loads(handler.rfile.read(int(handler.headers["Content-Length"])))

        # Validate account format
        class _APIErrorResponse(Exception): pass
        try:
            if not re.match(r"\w+@[\w\.-]+$", obj["acc"]): raise _APIErrorResponse("Invalid account format.")
            cn, domain = obj["acc"].split("@")
            if domain != mgr.domain: raise _APIErrorResponse("Invalid domain name.")

            # Change password
            try:
                mgr.connect(cn, obj["cur"])
                mgr.change_user_password(cn, obj["npw"], obj["cur"])
            except UserOperationFailed as e:
                raise _APIErrorResponse(str(e))
            except Exception as e:
                traceback.print_exc(e)
                raise _APIErrorResponse(str(e))
        except _APIErrorResponse as e:
            return "application/json", json.dumps({"success": False, "message": str(e)})

        return "application/json", json.dumps({"success": True})

    def run():
        addr, port = bind_addr.split(":")
        server_address = (addr, int(port))
        httpd = HTTPServer(server_address, TinyHTTPRequestHandler)
        httpd.serve_forever()

    run()

HTML_FORM = """<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>ADLeastCLI Change password</title>
  <style>
  h1 { margin: 0; font-size: 24px; }
  label { display: block; font-weight: bold; margin-top: 8px; }
  input, button { font-size: 14px; border-radius: 5px; }
  input { border: 1px solid #999; width: calc(100% - 10px); padding: 4px; }
  button { border-style: none; margin-top: 12px; padding: 8px 12px; cursor: pointer; }
  .container { max-width: 300px; }
  </style>
</head>
<body>
  <h1>Change Password</h1>
  <div class="container">
    <label>Account</label>
    <input id="txtAccount" type="text" placeholder="username@example.com">
    <label>Current password</label><input id="txtCurrent" type="password">
    <label>New password</label><input id="txtNewPass" type="password">
    <label>Confirm password</label><input id="txtConfirm" type="password">
    <button id="cmdOK">Change password</button>
  </div>
  <script>
  document.querySelector("#cmdOK").addEventListener("click", function() {
    var h = {
      acc: document.querySelector("#txtAccount").value,
      cur: document.querySelector("#txtCurrent").value,
      npw: document.querySelector("#txtNewPass").value
    };

    if(h.npw != document.querySelector("#txtConfirm").value){
        alert("New password and confirmation do not match!!");
        return;
    }

    fetch("api/passwd", {method: "POST", body: JSON.stringify(h)})
    .then(function(res){ return res.json(); })
    .then(function(data){
        if(data.success){
            alert("Password has been changed.");
            document.querySelector("#txtCurrent").value = "";
            document.querySelector("#txtNewPass").value = "";
            document.querySelector("#txtConfirm").value = "";
        }else{
            alert(data.message);
        }
    });
  });
  </script>
</body>
</html>
"""

if __name__ == "__main__":
    import sys, argparse
    from getpass import getpass

    EPILOG = """example:
    Create a user
    $ adleastcli -S example.com user create testuser Password123#

    Create a group
    $ adleastcli -S example.com group create mygroup

    Add the user to the group
    $ adleastcli -S example.com user join testuser mygroup

    Remove the user from the group
    $ adleastcli -S example.com user leave testuser mygroup

    Delete a group
    $ adleastcli -S example.com group delete mygroup

    Delete a user
    $ adleastcli -S example.com user delete testuser

    List users
    $ adleastcli -S example.com user

    Show user details
    $ adleastcli -S example.com user info testuser

    List groups
    $ adleastcli -S example.com group

    Show group details
    $ adleastcli -S example.com group info mygroup

    Set password(as administrator)
    $ adleastcli -S example.com user setpw testuser NewPass123#

    Change password(as a user)
    $ adleastcli -S example.com -U testuser user passwd

    Start WebUI server for changing password by oneself
    $ adleastcli -S example.com httpd
    """

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="ADLeastCLI: AD User Manager",
        epilog=EPILOG
    )
    parser.add_argument("target", choices=["user", "group", "httpd"], help="Operation target")
    parser.add_argument("target_args", metavar="ARGS", type=str, nargs="*", help="Operation arguments")
    parser.add_argument("-S", dest="domain", required=True, help="Domain (required)")
    parser.add_argument("-U", dest="user", default="Administrator", help="Operator username (default: Administrator)")
    parser.add_argument("-b", dest="bindaddr", default="0.0.0.0:8080", help="Bind address for httpd (default: 0.0.0.0:8080)")
    args = parser.parse_args()
    mgr = UserManager(args.domain)

    if args.target == "httpd":
        # Start simple httpd server
        # This is not recommended for production use.
        sys.stderr.write("Start changing password Web UI for '{}'.\n".format(args.domain))
        sys.stderr.write("Bind address: {}\n".format(args.bindaddr))
        try:
            start_web_server(mgr, args.bindaddr)
        except KeyboardInterrupt:
            sys.stderr.write("Server stopped.\n")
            sys.exit(1)

    ADM_USER = args.user
    ADM_PASS = getpass("Enter password for {}: ".format(ADM_USER))

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
