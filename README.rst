=============================
 ADLeastCLI: AD User Manager
=============================

Overview
========

*ADLeastCLI* provides least operations for managing users/groups on Active
Directory(AD).

When you want to use an AD for only authentication (i.e. AWS Client VPN with
Directory Service), it can manage users/groups with very simple procedure.

Example::

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
    Enter password for testuser:
    Enter new password:
    Confirm new password:
