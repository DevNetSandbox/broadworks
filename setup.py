'''
sample code: create a user under your group and assign service for the user using OCI-P APIs
'''

import BwksAPIOperations

def setup():
    #config 
    xsp = "broadsoftsandboxxsp.cisco.com"
    group_name = "zowu-Grp1"  #use your own group name
    provisioner = "zowu-Grp1" #use your own group admin account
    provisioner_passwd = "cisco123"
    enter_id = "DevNet"
    domain = "broadsoftlab.com"
    user_password = "cisco123"

    #init oci_session object
    OCI_Session = BwksAPIOperations.BwksAPIOperations("http://{0}".format(xsp), username=provisioner, password = provisioner_passwd, domain=domain)

    #get next available DN in the group
    resp = OCI_Session.GroupDnGetAvailableListRequest(enter_id, group_name)
    print(resp)
    tree_dn_list =  OCI_Session.get_xml_section_content(resp, "//phoneNumber")
    dn_pool = OCI_Session.get_xml_param_all_value(tree_dn_list, ".")[0]
    #parse the string list to actual list
    first_dn = dn_pool.split()[0]

    #create the new user 
    print("Create user u{0}".format(first_dn))
    resp = OCI_Session.UserAddRequest22(enter_id, group_name, "u{0}@{1}".format(first_dn, domain), "L{0}".format(first_dn), "F{0}".format(first_dn), first_dn, first_dn[-4:], user_password)
    print(resp)

    #add line port for the user
    resp = OCI_Session.UserModifyRequest22("u{0}".format(first_dn),first_dn,first_dn[-4:],"GenericSIP","{0}@{1}".format(first_dn, domain))
    print(resp)
    if not "SuccessResponse" in resp:
        return False

    #assign services for the user
    resp = OCI_Session.UserServiceAssignListRequest("u{0}".format(first_dn), "", ["Authentication","Calling Name Delivery","Calling Number Delivery"], ["Basic"])
    print(resp)
    if not "SuccessResponse" in resp:
        return False

    #assign authentication for the user
    resp = OCI_Session.UserAuthenticationModifyRequest(user_id = "u{0}".format(first_dn), user_name = "u{0}".format(first_dn), user_password = user_password)
    print(resp)
    if not "SuccessResponse" in resp:
        return False


if __name__ == '__main__':
    setup()
