# Module for accessing OCI, BroadSoft soap api for working with BroadWorks instances

import time, datetime, logging
from logging import getLogger
import requests
from requests.adapters import HTTPAdapter
import hashlib
from lxml import etree
import re
import sys


try:
    import leotestcase
except:
    pass

   
class BwksAPIOperations():
    LOGNAME = "BROADWORKS OCI: "

    value = ""
    cookie = ""
    sessionId = ""
    nonce = ""

    def __init__(self, url, username, password, domain, provisioning_service="/webservice/services/ProvisioningService", country_code='+1-'):
        self._url = url
        self._username = username
        self._password = password
        self._domain = domain
        self._set_session_id()
        self._provisioning_service = provisioning_service
        self._country_code = country_code

    def _set_session_id(self):
        self.sessionId = str(int(round(time.time() * 1000)))

    def _get_request_head(self, command):
        # command and BroadsoftDocument tags should be encoded
        head = """<?xml version="1.0" encoding="UTF-8"?>
                  <soapenv:Envelope
                  xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                  <soapenv:Body>
                  <processOCIMessage soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                  <arg0 xsi:type="soapenc:string" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
                  &lt;BroadsoftDocument protocol=&quot;OCI&quot; xmlns=&quot;C&quot; xmlns:xsi=&quot;http://www.w3.org/2001/XMLSchema-instance&quot;&gt;
                  &lt;sessionId xmlns=&quot;&quot;&gt;""" + self.sessionId + """&lt;/sessionId&gt;
                  &lt;command xsi:type=&quot;""" +command+ """&quot; xmlns=&quot;&quot;&gt;
               """
        return head

    def _get_request_tail(self,command):
        # command and BroadsoftDocument tags should be encoded
        tail = """&lt;/command&gt;
                  &lt;/BroadsoftDocument&gt;
                  </arg0>
                  </processOCIMessage>
                  </soapenv:Body>
                  </soapenv:Envelope>
               """
        return tail

    def _generate_request_body(self, command, req):

        body = self._get_request_head(command) +"  " + req + self._get_request_tail(command)
        return body

    def AuthenticationRequest(self, login):
        reqst = """
        <userId>""" + login + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("AuthenticationRequest", req)
        logging.info(self.LOGNAME + "Send auth request to BWKS (" + self._url + self._provisioning_service + "): " + self.__pretty_text_log(request))
        return request

    def LoginRequest14sp4(self, login, password):
        reqst = """
        <userId>""" + login + """</userId>
        <signedPassword>""" + password + """</signedPassword>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("LoginRequest14sp4", req)
        logging.debug(self.LOGNAME + "Send request to login to BWKS: " + self.__pretty_text_log(request))
        return request

    def LoginRequest22(self, login, password):
        reqst = """
        <userId>""" + login + """</userId>
        <password>""" + password + """</password>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("LoginRequest22", req)
        logging.debug(self.LOGNAME + "Send request to login to BWKS: " + self.__pretty_text_log(request))
        return request

    def LoginRequest(self, login, password):
        headers = {
            'SOAPAction': 'processOCIMessage'
        }
        s = requests.Session()
        s.mount('http://', HTTPAdapter(max_retries=30))
        s.mount('https://', HTTPAdapter(max_retries=30))

        logging.info(self.LOGNAME + "Send request to login to BWKS")
        rauth = s.post(self._url + self._provisioning_service, data=self.AuthenticationRequest(login),
                       verify=False, headers=headers)
        auth_cookie = rauth.cookies
        logging.debug(self.LOGNAME + "Auth Response is: " + self.__pretty_text_log(rauth.text))
        self.__store_nonce(self.__pretty_text(rauth.text))
        passw = hashlib.md5(self.nonce + ':' + password).hexdigest()
        print(passw, password)
        reqst = """
        <userId>""" + login + """</userId>
        <signedPassword>""" + passw + """</signedPassword>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("LoginRequest14sp4", req)
        logging.debug(self.LOGNAME + "Login Request is: " + self.__pretty_text_log(request))
        rlogin = s.post(self._url + self._provisioning_service, data=request, verify=False,
                        headers=headers, cookies=auth_cookie)
        logging.debug(self.LOGNAME + "Login Response is: " + self.__pretty_text_log(rlogin.text))
        return self.__pretty_text(rlogin.text)

    def LogoutRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to logout a user " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("LogoutRequest", req)
        response = self.__send_request(request)
        return response

    def SystemDomainAddRequest(self, domain_add):
        logging.info(self.LOGNAME + "Send request to BWKS to add Domain " + domain_add)
        reqst = """
        <domain>""" + domain_add + """</domain>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemDomainAddRequest", req)
        response = self.__send_request(request)
        return response

    def SystemDomainDeleteRequest(self, domain):
        logging.info(self.LOGNAME + "Send request to BWKS to delete System Domain " + domain)
        reqst = """
        <domain>""" + domain + """</domain>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemDomainDeleteRequest", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderAddRequest13mp2(self, ent_id, ent_name=None):
        logging.info(self.LOGNAME + "Send request to BWKS to add Enterprise " + ent_id)
        if ent_name is None:
            ent_name = ent_id
        reqst = """
        <isEnterprise>true</isEnterprise>
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <defaultDomain>""" + self._domain + """</defaultDomain>
        <serviceProviderName>""" + ent_name + """</serviceProviderName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderAddRequest13mp2", req)
        response = self.__send_request(request)

        return response


    def SystemServiceProviderAddRequest13mp2(self, ent_id, ent_name=None, use_custom_profile='false'):
        logging.info(self.LOGNAME + "Send request to BWKS to add Enterprise " + ent_id)
        if ent_name is None:
            ent_name = ent_id
        reqst = """
        <useCustomRoutingProfile>""" + use_custom_profile + """</useCustomRoutingProfile>
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <defaultDomain>""" + self._domain + """</defaultDomain>
        <serviceProviderName>""" + ent_name + """</serviceProviderName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderAddRequest13mp2", req)
        response = self.__send_request(request)

        return response

    def ServiceProviderGetRequest(self, starts_with, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve Enterprise " + ent_id)
        reqst = """
        <searchCriteriaServiceProviderId>
        <mode>""" + starts_with + """</mode>
        <value>""" + ent_id + """</value>
        </searchCriteriaServiceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderGetRequest", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderGetRequest13mp2(self, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve Enterprise " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderGetRequest13mp2", req)
        response = self.__send_request(request)
        return response
    

    def ServiceProviderGetRequest17sp1(self, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve Enterprise " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderGetRequest17sp1", req)
        response = self.__send_request(request)
        return response



    def ServiceProviderDomainAssignListRequest(self, ent_id, domain):
        logging.info(self.LOGNAME + "Send request to BWKS to add domain to the Enterprise " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <domain>""" + domain + """</domain>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderDomainAssignListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupPasswordRulesGetRequest16(self, ent_id, group_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve Password rules of group " + group_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupPasswordRulesGetRequest16", req)
        response = self.__send_request(request)
        return response

    def GroupPasswordRulesModifyRequest(self, ent_id, group_id, ppolicy_data):
        logging.info(self.LOGNAME + "Send request to BWKS to modify Password rules of group " + group_id)
        reqst = """
            <serviceProviderId>""" + ent_id + """</serviceProviderId>
            <groupId>""" + group_id + """</groupId>
             <disallowUserId>""" + ppolicy_data['disallowUserId'] + """</disallowUserId>
            <disallowOldPassword>true</disallowOldPassword>
            <disallowReversedOldPassword>true</disallowReversedOldPassword>
            <restrictMinDigits>""" + ppolicy_data['restrictMinDigits'] + """</restrictMinDigits>
            <minDigits>""" + ppolicy_data['minDigits'] + """</minDigits>
            <restrictMinUpperCaseLetters>""" + ppolicy_data['restrictMinUpperCaseLetters'] +"""</restrictMinUpperCaseLetters>
            <minUpperCaseLetters>""" + ppolicy_data['minUpperCaseLetters'] + """</minUpperCaseLetters>
            <restrictMinLowerCaseLetters>""" + ppolicy_data['restrictMinLowerCaseLetters'] + """</restrictMinLowerCaseLetters>
            <minLowerCaseLetters>""" + ppolicy_data['minLowerCaseLetters'] + """</minLowerCaseLetters>
            <restrictMinNonAlphanumericCharacters>""" + ppolicy_data['restrictMinNonAlphanumericCharacters'] + """</restrictMinNonAlphanumericCharacters>
            <minNonAlphanumericCharacters>""" + ppolicy_data['minNonAlphanumericCharacters'] + """</minNonAlphanumericCharacters>
            <minLength>""" + ppolicy_data['minLength'] + """</minLength>
            <maxFailedLoginAttempts>5</maxFailedLoginAttempts>
            <passwordExpiresDays>30</passwordExpiresDays>
            <sendLoginDisabledNotifyEmail>false</sendLoginDisabledNotifyEmail>
            <loginDisabledNotifyEmailAddress xsi:nil="true"/>
            <disallowPreviousPasswords>false</disallowPreviousPasswords>
            <numberOfPreviousPasswords>2</numberOfPreviousPasswords>
            """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupPasswordRulesModifyRequest", req)
        response = self.__send_request(request)

        return response

    def UserTimeScheduleAddRequest(self, user_id, time_schedule):
        logging.info(
            self.LOGNAME + "Send request to BWKS to add Time schedule '%s' to user '%s'" % (time_schedule, user_id))
        reqst = """
        <userId>""" + user_id + """</userId>
        <timeScheduleName>""" + time_schedule + """</timeScheduleName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserTimeScheduleAddRequest", req)
        response = self.__send_request(request)
        return response

    def UserTimeScheduleDeleteRequest(self, user_id, time_schedule):
        logging.info(self.LOGNAME + "Send request to BWKS to delete Time schedule '%s' from user '%s'" % (
        time_schedule, user_id))
        reqst = """
        <userId>""" + user_id + """</userId>
        <timeScheduleName>""" + time_schedule + """</timeScheduleName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserTimeScheduleDeleteRequest", req)
        response = self.__send_request(request)
        return response

    def UserScheduleDeleteListRequest(self, user_id, schedule_name, type):
        logging.info(
            self.LOGNAME + "Send request to BWKS to delete schedule '%s' from user '%s'" % (schedule_name, user_id))
        reqst = """
        <userId>""" + user_id + """</userId>
        <scheduleKey>
          <scheduleName>""" + schedule_name + """</scheduleName>
          <scheduleType>""" + type + """</scheduleType>
        </scheduleKey>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserScheduleDeleteListRequest", req)
        response = self.__send_request(request)
        return response
    
    def UserHolidayScheduleAddRequest(self, user_id, Holiday_schedule):
        logging.info(
            self.LOGNAME + "Send request to BWKS to add Holiday schedule '%s' to user '%s'" % (Holiday_schedule, user_id))
        reqst = """
        <userId>""" + user_id + """</userId>
        <scheduleKey>
          <scheduleName>""" + Holiday_schedule + """</scheduleName>
          <scheduleType>Holiday</scheduleType>
        </scheduleKey>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserScheduleAddEventRequest", req)
        response = self.__send_request(request)
        return response

    def SystemPortalPasscodeRulesGetRequest19(self):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve System Passcode rules")
        reqst = """
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemPortalPasscodeRulesGetRequest19", req)
        response = self.__send_request(request)
        return response

    def UserBroadWorksMobilityGetRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve Broadworks Mobility settings of user: " + user_id)
        reqst = """ <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserBroadWorksMobilityGetRequest", req)
        response = self.__send_request(request)
        return response

    def UserInterceptUserGetRequest16sp1(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve Intercept User settings of user: " + user_id)
        reqst = """ <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserInterceptUserGetRequest16sp1", req)
        response = self.__send_request(request)

        return response

    def UserBroadWorksMobilityGetRequest21(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve Broadworks Mobility settings of user: " + user_id)
        reqst = """ <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserBroadWorksMobilityGetRequest21", req)
        response = self.__send_request(request)
        return response

    def UserBroadWorksMobilityMobileIdentityDeleteRequest(self, user_id, bwks_mobility):
        logging.info(self.LOGNAME + "Send request to BWKS to delete Broadworks Mobility of user: " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        <mobileNumber>""" + bwks_mobility + """</mobileNumber>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserBroadWorksMobilityMobileIdentityDeleteRequest", req)
        response = self.__send_request(request)

        return response

    def GroupCollaborateBridgeDeleteInstanceRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to delete Collaborate Bridge: " + user_id)
        reqst = """
        <serviceUserId>""" + user_id + """</serviceUserId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCollaborateBridgeDeleteInstanceRequest", req)
        response = self.__send_request(request)

        return response

    def UserBroadWorksMobilityModifyRequest21(self, user_id, dict_1={}):
        logging.info(self.LOGNAME + "Send request to BWKS to modify Broadworks Mobility of user: " + user_id)
        dict_2 = {}
        dict_2['isActive'] = 'false'
        dict_2['useMobileIdentityCallAnchoring'] = 'true'
        dict_2['preventCallsToOwnMobiles'] = 'false'
        dict_2['mobileIdentity'] = {}
        dict_2['mobileIdentity']['mobileNumber'] = user_id
        dict_2['mobileIdentity']['isPrimary'] = 'true'
        dict_2['mobileIdentity']['enableAlerting'] = 'true'

        #merge two dictionaries to the third which will be used in request
        if dict_1:
            bwks_mobility_data = dict_2.copy()
            bwks_mobility_data.update(dict_1)
        else:  # Use default values
            bwks_mobility_data = dict_2
        reqst = """
        <isActive>""" + bwks_mobility_data['isActive'] + """</isActive>
        <useMobileIdentityCallAnchoring>""" + bwks_mobility_data['useMobileIdentityCallAnchoring'] + """</useMobileIdentityCallAnchoring>
        <preventCallsToOwnMobiles>""" + bwks_mobility_data['preventCallsToOwnMobiles'] + """</preventCallsToOwnMobiles>
        <mobileIdentity>
            <mobileNumber>""" + bwks_mobility_data['mobileIdentity']['mobileNumber'] + """</mobileNumber>
            <isPrimary>""" + bwks_mobility_data['mobileIdentity']['isPrimary'] + """</isPrimary>
            <enableAlerting>""" + bwks_mobility_data['mobileIdentity']['enableAlerting'] + """</enableAlerting>
        </mobileIdentity>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserBroadWorksMobilityModifyRequest21", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderPortalPasscodeRulesGetRequest19(self, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve Passcode rules of enterprise " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderPortalPasscodeRulesGetRequest19", req)
        response = self.__send_request(request)

        return response

    def GroupPortalPasscodeRulesGetRequest19(self, ent_id, group_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve Passcode rules of group " + group_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupPortalPasscodeRulesGetRequest19", req)
        response = self.__send_request(request)

        return response

    def ServiceProviderGetListRequest(self, withSP=True):
        logging.info(self.LOGNAME + "Send request to BWKS to get all Enterprises and Service Providers")
        # Ents
        reqst = """
        <isEnterprise>true</isEnterprise>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderGetListRequest", req)
        response = self.__send_request(request)
        table = self.get_xml_section_content(response, "//serviceProviderTable")
        all_ents = self.get_xml_param_all_value(table, ".//row/col[1]")
        if not withSP:
            return all_ents
        # Service providers
        reqst = """
        <isEnterprise>false</isEnterprise>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderGetListRequest", req)
        response = self.__send_request(request)
        table = self.get_xml_section_content(response, "//serviceProviderTable")
        all_sps = self.get_xml_param_all_value(table, ".//row/col[1]")
        return all_ents + all_sps

    def SystemDomainGetListRequest(self):
        logging.info(self.LOGNAME + "Send request to BWKS to get all system domains")
        req = ""
        request = self._generate_request_body("SystemDomainGetListRequest", req)
        response = self.__send_request(request)
        table = self.get_xml_section_content(response, "//command")
        domains = self.get_xml_param_all_value(table, ".//domain")
        return domains


    def UserBusyLampFieldGetRequest(self, user):
        logging.info(self.LOGNAME + "Send request to BWKS to get 'Busy Lamp Field' info about user: " + user)
        reqst = """
        <userId>""" + user + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserBusyLampFieldGetRequest16sp2", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderDeleteRequest(self, ent_id, try_to_delete_groups=False):
        logging.info(self.LOGNAME + "Send request to BWKS to delete Enterprise " + ent_id)
        if try_to_delete_groups:
            logging.info(self.LOGNAME + "Try to delete all Groups from Ent first")
            groups_xml = self.GroupGetListInServiceProviderRequest(ent_id)
            # print groups_xml
            if "groupTable" in groups_xml:
                table = self.get_xml_section_content(groups_xml, "//groupTable")
                groups = self.get_xml_param_all_value(table, ".//row/col[1]")
                logging.debug(self.LOGNAME + "Groups are: " + str(groups))
                for group in groups:
                    self.GroupDeleteRequest(ent_id, group)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderDeleteRequest", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderTrunkGroupGetRequest14sp1(self, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve Enterprise Trunk Group options " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderTrunkGroupGetRequest14sp1", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderAdminAddRequest14(self, ent_id, admin, adm_type, pw="leoBr00me!"):
        logging.info(self.LOGNAME + "Send request to BWKS to add Enterprise admin " + admin)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <userId>""" + admin + """</userId>
        <password>""" + pw + """</password>
        <language>English</language>
        <administratorType>""" + adm_type + """</administratorType>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderAdminAddRequest14", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderAdminGetRequest(self, admin):
        logging.info(self.LOGNAME + "Send request to BWKS to get Enterprise admin " + admin)
        reqst = """
        <userId>""" + admin + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderAdminGetRequest", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderAdminGetRequest14(self, admin):
        logging.info(self.LOGNAME + "Send request to BWKS to get Enterprise admin " + admin)
        reqst = """
        <userId>""" + admin + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderAdminGetRequest14", req)
        response = self.__send_request(request)
        return response

    def GroupAdminGetRequest(self, admin):
        logging.info(self.LOGNAME + "Send request to BWKS to get Group admin " + admin)
        reqst = """
        <userId>""" + admin + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAdminGetRequest", req)
        response = self.__send_request(request)

        return response

    def GroupDepartmentAdminGetRequest(self, admin):
        logging.info(self.LOGNAME + "Send request to BWKS to get Group admin " + admin)
        reqst = """
        <userId>""" + admin + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupDepartmentAdminGetRequest", req)
        response = self.__send_request(request)

        return response

    def ServiceProviderAdminModifyRequest(self, admin):
        logging.info(self.LOGNAME + "Send request to BWKS to modify Enterprise admin " + admin.admin_id)
        reqst = """
        <userId>""" + admin.admin_id + """</userId>"""

        if admin.admin_fname != '':
            reqst += """
            <firstName>""" + admin.admin_fname + """</firstName>
            """

        if admin.admin_lname != '':
            reqst += """
            <lastName>""" + admin.admin_lname + """</lastName>
            """

        reqst += """
        <password>""" + admin.admin_pw + """</password>
        <language>English</language>
        """



        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderAdminModifyRequest", req)
        response = self.__send_request(request)
        return response

    def SystemStateOrProvinceGetListRequest(self):
        logging.info(self.LOGNAME + "Send request to BWKS to get all State/Province")
        reqst = """
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemStateOrProvinceGetListRequest", req)
        response = self.__send_request(request)

        return response


    def GroupModifyRequest(self, ent_id, group_id, dict_1={}):
        logging.info(self.LOGNAME + "Send request to BWKS to modify Group: '" + ent_id + ":" + group_id + "'")
        # Define default values for request
        dict_2 = {}
        dict_2['timeZone'] = 'America/New_York'
        # Let`s merge two dictionaries to the third which will be used in request
        if dict_1:
            user_data = dict_2.copy()
            user_data.update(dict_1)
        else:  # Use default values
            user_data = dict_2
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <timeZone>""" + user_data['timeZone'] + """</timeZone>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupModifyRequest", req)
        response = self.__send_request(request)
        return response

    def GroupModifyCLIDNumberRequest(self, ent_id, group_id, dict_1={}):
        logging.info(self.LOGNAME + "Send request to BWKS to modify Group: '" + ent_id + ":" + group_id + "'")
        # Define default values for request
        dict_2 = {}
        dict_2['timeZone'] = 'America/New_York'
        # Let`s merge two dictionaries to the third which will be used in request
        if dict_1:
            user_data = dict_2.copy()
            user_data.update(dict_1)
        else:  # Use default values
            user_data = dict_2
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <defaultDomain>""" + self._domain + """</defaultDomain>
        <userLimit>1000</userLimit>
        <groupName>""" + group_id + """</groupName>"""
        if "callingLineIdPhoneNumber" in user_data:
            reqst += """<callingLineIdName>""" + user_data['callingLineIdPhoneNumber'][-5:] + """CLID</callingLineIdName>""" + """
        <callingLineIdPhoneNumber>""" + user_data['callingLineIdPhoneNumber'] + """</callingLineIdPhoneNumber>
        <timeZone>""" + user_data['timeZone'] + """</timeZone>
        <locationDialingCode xsi:nil="true"/>
        <contact>
          <contactName xsi:nil="true"/>
          <contactNumber xsi:nil="true"/>
          <contactEmail xsi:nil="true"/>
        </contact>
        <address>
          <addressLine1 xsi:nil="true"/>
          <addressLine2 xsi:nil="true"/>
          <city xsi:nil="true"/>
          <stateOrProvince xsi:nil="true"/>
          <zipOrPostalCode xsi:nil="true"/>
          <country xsi:nil="true"/>
        </address>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupModifyRequest", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderAdminDeleteRequest(self, admin):
        logging.info(self.LOGNAME + "Send request to BWKS to delete Enterprise admin " + admin)
        reqst = """
        <userId>""" + admin + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderAdminDeleteRequest", req)
        response = self.__send_request(request)

        return response

    def ServiceProviderTrunkGroupModifyRequest(self, ent_id, active, bursting):
        logging.info(self.LOGNAME + "Send request to BWKS to set trunking call capacity for Enterprise " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <maxActiveCalls>
          <quantity>""" + active + """</quantity>
        </maxActiveCalls>
        <burstingMaxActiveCalls>
          <quantity>""" + bursting + """</quantity>
        </burstingMaxActiveCalls>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderTrunkGroupModifyRequest", req)
        response = self.__send_request(request)
        return response

    def GroupDepartmentAddRequest(self, ent_id, grp_id, name,parent={}):
        logging.info(self.LOGNAME + "Send request to BWKS to add department " + name)
        if parent == {}:
            
            reqst = """<serviceProviderId>""" + ent_id + """</serviceProviderId>
            <groupId>""" + grp_id + """</groupId>
            <departmentName>""" + name + """</departmentName>
            """
        else:
            reqst="""<serviceProviderId>""" + ent_id + """</serviceProviderId>
            <groupId>""" + grp_id + """</groupId>
            <departmentName>""" + name + """</departmentName>
            <parentDepartmentKey xsi:type="GroupDepartmentKey">
            <serviceProviderId>""" + parent["serviceprovider_id"]+ """</serviceProviderId>
            
            
      <groupId>""" + parent["group_id"] +"""</groupId>
      <name>""" + parent["name"] +"""</name>
    </parentDepartmentKey>
            """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupDepartmentAddRequest", req)
        response = self.__send_request(request)

        return response

    def GroupTrunkGroupGetInstanceListRequest14sp4(self, pattern):
        request = pattern.get_all_sections()

        request = request.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupTrunkGroupGetInstanceListRequest14sp4", request)
        logging.debug(self.LOGNAME + "Send GroupTrunkGroupGetInstanceListRequest14sp4 to LWS: " + request)
        response = self.__send_request(request)

        return response

    def SendRequestPattern(self, pattern, request_name):
        request = pattern.get_all_sections()

        request = request.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body(request_name, request)
        logging.debug(self.LOGNAME + "Send " + request_name + " to Bwks: " + request)
        response = self.__send_request(request)

        return response

    def GroupIncomingCallingPlanModifyListRequest(self, pattern):
        request = pattern.get_all_sections()

        request = request.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupIncomingCallingPlanModifyListRequest", request)
        logging.debug(self.LOGNAME + "Send GroupIncomingCallingPlanModifyListRequest to LWS: " + request)
        response = self.__send_request(request)

        return response

    def GroupIncomingCallingPlanGetListRequest(self, ent_id, grp_id):
        reqst = """<serviceProviderId>""" + ent_id + """</serviceProviderId>
    <groupId>""" + grp_id + """</groupId>
        """

        request = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupIncomingCallingPlanGetListRequest", request)
        logging.debug(self.LOGNAME + "Send GroupIncomingCallingPlanGetListRequest to LWS: " + request)
        response = self.__send_request(request)

        return response

    def GroupDepartmentDeleteRequest(self, ent_id, grp_id, name):
        logging.info(self.LOGNAME + "Send request to BWKS to delete department " + name)
        reqst = """<serviceProviderId>""" + ent_id + """</serviceProviderId>
    <groupId>""" + grp_id + """</groupId>
    <departmentName>""" + name + """</departmentName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupDepartmentDeleteRequest", req)
        response = self.__send_request(request)
        return response

    def GroupDomainAssignListRequest(self, ent_id, grp_id, domain):
        logging.info(self.LOGNAME + "Send request to BWKS to add domain to Group " + domain)
        reqst = """<serviceProviderId>""" + ent_id + """</serviceProviderId>
    <groupId>""" + grp_id + """</groupId>
    <domain>""" + domain + """</domain>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupDomainAssignListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupAdminAddRequest(self, ent_id, grp_id, admin_id, admin_fname, admin_lname, admin_pw):
        logging.info(self.LOGNAME + "Send request to BWKS to add group admin " + admin_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        <userId>""" + admin_id + """</userId>
        <firstName>""" + admin_fname + """</firstName>
        <lastName>""" + admin_lname + """</lastName>
        <password>""" + admin_pw + """</password>
        <language>English</language>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAdminAddRequest", req)
        response = self.__send_request(request)

        return response

    def GroupAdminAddRequest_dict(self, ent_id, grp_id, admin, reset_pw=True):
        logging.info(self.LOGNAME + "Send request to BWKS to add group admin " + admin["admin_id"])
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        <userId>""" + admin["admin_id"] + '@' + admin["domain"] + """</userId>"""

        if 'fname' in admin:
            reqst += "<firstName>" + admin["fname"] + "</firstName>"

        if 'lname' in admin:
            reqst += "<lastName>" + admin["lname"] + "</lastName>"

        reqst += """<password>""" + admin["password"] + """</password>
        <language>""" + admin["language"] + """</language>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAdminAddRequest", req)
        response = self.__send_request(request)
        if reset_pw:
            self.PasswordModifyRequest_dict(admin, admin["password"])
        return response

    def GroupAdminGetListRequest(self, ent_id, grp_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get group admins from Group " + grp_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAdminGetListRequest", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderAdminGetListRequest14(self, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get group admins from Ent " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderAdminGetListRequest14", req)
        response = self.__send_request(request)
        return response

    def GroupCallCenterGetSupervisorListRequest(self, cc_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get list of supervisors for Call Center: " + cc_id)
        reqst = """
        <serviceUserId>""" + cc_id + """</serviceUserId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallCenterGetSupervisorListRequest16", req)
        response = self.__send_request(request)
        return response

    def GroupDepartmentAdminAddRequest(self, ent_id, grp_id, admin, dep_name, reset_pw=True):
        logging.info(self.LOGNAME + "Send request to BWKS to add department admin " + admin.admin_id)
        reqst = """<departmentKey>
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        <name>""" + dep_name + """</name>
        </departmentKey>
        <userId>""" + admin.admin_id + """</userId>
        <password>""" + admin.admin_pw + """</password>
        <language>English</language>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupDepartmentAdminAddRequest", req)
        response = self.__send_request(request)
        if reset_pw:
            self.PasswordModifyRequest(admin, admin.admin_pw)
        return response

    def SystemAdminAddRequest(self, admin, admin_type, reset_pw=True,
                              readonly="false"):  # admin type = "System" or "Provisioning", readonly = "true" or "false"
        logging.info(self.LOGNAME + "Send request to BWKS to add " + admin_type + " admin " + admin.admin_id)
        reqst = """
        <userId>""" + admin.admin_id + """</userId>
        <password>""" + admin.admin_pw + """</password>
        <language>English</language>
        <adminType>""" + admin_type + """</adminType>
        <readOnly>""" + readonly + """</readOnly>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemAdminAddRequest", req)
        response = self.__send_request(request)
        if reset_pw:
            self.PasswordModifyRequest(admin, admin.admin_pw)
        return response

    def SystemAdminDeleteRequest(self, admin):
        logging.info(self.LOGNAME + "Send request to BWKS to delete System/Provisioning admin " + admin.admin_id)
        reqst = """
        <userId>""" + admin.admin_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemAdminDeleteRequest", req)
        response = self.__send_request(request)
        return response
    
    def ll(self, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to display User PreAlerting Announcements")
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserPreAlertingAnnouncementGetRequest20", req)
        response = self.__send_request(request)
        return response 


    def SystemAdminDeleteRequestSimple(self, admin):
        logging.info(self.LOGNAME + "Send request to BWKS to delete System/Provisioning admin " + admin)
        reqst = """
        <userId>""" + admin + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemAdminDeleteRequest", req)
        response = self.__send_request(request)

        return response

    def SystemAdminGetListRequest(self):
        logging.info(self.LOGNAME + "Send request to BWKS to get list of all System/Provisioning admins")
        reqst = """ """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemAdminGetListRequest", req)
        response = self.__send_request(request)
        table = self.get_xml_section_content(response, "//systemAdminTable")
        all_admins = self.get_xml_param_all_value(table, ".//row/col[1]")
        return all_admins

    def PasswordModifyRequest(self, admin, new_pass):
        logging.info(self.LOGNAME + "Send request to BWKS to change password for " + admin.admin_id)
        reqst = """
        <userId>""" + admin.admin_id + """</userId>
        <oldPassword>""" + admin.admin_pw + """</oldPassword>
        <newPassword>""" + new_pass + """</newPassword>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("PasswordModifyRequest", req)
        response = self.__send_request(request)
        return response

    def PasswordModifyRequest_dict(self, admin, new_pass):
        logging.info(self.LOGNAME + "Send request to BWKS to change password for " + admin["admin_id"])
        reqst = """
        <userId>""" + admin["admin_id"] + """</userId>
        <oldPassword>""" + admin["password"] + """</oldPassword>
        <newPassword>""" + new_pass + """</newPassword>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("PasswordModifyRequest", req)
        response = self.__send_request(request)
        return response

    def userPasswordModifyRequest(self, user_id, new_pass):
        logging.info(self.LOGNAME + "Send request to BWKS to change password for " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        <newPassword>""" + new_pass + """</newPassword>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("PasswordModifyRequest", req)
        response = self.__send_request(request)
        return response
    
    def EnterprisePreAlertingAnnounRequest(self, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to display enterprise PreAlerting Announcements")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("EnterprisePreAlertingAnnouncementGetRequest", req)
        response = self.__send_request(request)
        return response 
    
    def GroupPreAlertingAnnounRequest(self, ent_id, grp_id):
        logging.info(self.LOGNAME + "Send request to BWKS to display enterprise PreAlerting Announcements")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupPreAlertingAnnouncementGetRequest", req)
        response = self.__send_request(request)
        return response 

    def GroupAdminDeleteRequest(self, admin, type_admin='group'):
        if type_admin == 'group':
            logging.info(self.LOGNAME + "Send request to BWKS to delete group admin " + admin)
        else:
            logging.info(self.LOGNAME + "Send request to BWKS to delete department admin " + admin)
        reqst = """
        <userId>""" + admin + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        if type_admin == 'group':
            request = self._generate_request_body("GroupAdminDeleteRequest", req)
        else:
            request = self._generate_request_body("GroupDepartmentAdminDeleteRequest", req)
        response = self.__send_request(request)
        return response

    def GroupGetListInServiceProviderRequest(self, ent_id):
        logging.info(self.LOGNAME + "Send request to retrieve all groups in Enterprise " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupGetListInServiceProviderRequest", req)
        response = self.__send_request(request)
        return response

    def GroupAddRequest(self, ent_id, grp_id, grp_name, grp_contact, grp_phone, grp_email, grp_limit, group_service_names=[], user_service_names=[], sp_names=[]):
        logging.info(self.LOGNAME + "Send request to BWKS to add Group " + grp_id)
        if grp_name is None:
            grp_name = grp_id
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        <defaultDomain>""" + self._domain + """</defaultDomain>
        <userLimit>""" + grp_limit + """</userLimit>
        <groupName>""" + grp_name + """</groupName>
        <contact>
        <contactName>""" + grp_contact + """</contactName>
        <contactNumber>""" + grp_phone + """</contactNumber>
        <contactEmail>""" + grp_email + """</contactEmail>
        </contact>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAddRequest", req)
        response = self.__send_request(request)
        if user_service_names != [] or group_service_names != []:
            self.GroupServiceModifyAuthorizationListRequest(ent_id, grp_id,
                                                            group_service_names=group_service_names,
                                                            user_service_names=user_service_names)
            self.GroupServiceAssignListRequest(ent_id, grp_id, group_service_names=group_service_names)
        if sp_names != []:
            self.GroupServiceModifyAuthorizationListRequest(ent_id, grp_id, sp_names=sp_names)
        return response

    def EnterpriseCallCenterGetRoutingPolicyRequest(self, ent_id):
        logging.info(
            self.LOGNAME + "Send request to BWKS to retrieve Call Center Priorities for selected enterprise" + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("EnterpriseCallCenterGetRoutingPolicyRequest", req)
        response = self.__send_request(request)
        return response

    def GroupGetRequest(self, ent_id, grp_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve group " + grp_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupGetRequest", req)
        response = self.__send_request(request)
        return response

    def GroupCallProcessingGetPolicyRequest(self, ent_id, grp_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve call processing policy for group " + grp_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallProcessingGetPolicyRequest18", req)
        response = self.__send_request(request)
        return response

    def GroupCallProcessingModifyPolicyRequest(self, ent_id, grp_id, max_sim_calls=None,
                                               use_group_settings=None,
                                               use_group_call_limits_setting=None):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve call processing policy for group " + grp_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>"""
        if max_sim_calls is not None:
            reqst += """<maxSimultaneousCalls>""" + max_sim_calls + """</maxSimultaneousCalls>"""
        if use_group_settings is not None:
            reqst += """<useGroupCLIDSetting>""" + use_group_settings + """</useGroupCLIDSetting>"""
        if use_group_call_limits_setting is not None:
            reqst += """
            <useGroupMediaSetting>""" + use_group_call_limits_setting + """</useGroupMediaSetting>
            <useGroupCallLimitsSetting>""" + use_group_call_limits_setting + """</useGroupCallLimitsSetting>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallProcessingModifyPolicyRequest15sp2", req)
        response = self.__send_request(request)
        return response

    def GroupFeatureAccessCodeGetRequest(self, ent_id, grp_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve FAC codes of group: " + grp_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupFeatureAccessCodeGetRequest", req)
        response = self.__send_request(request)
        return response

    
    def GroupDeleteRequest(self, ent_id, grp_id):
        logging.info(self.LOGNAME + "Send request to BWKS to delete group " + grp_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupDeleteRequest", req)
        response = self.__send_request(request)
        return response

    def UserDeleteRequest(self, user_id, ent_id=None, group_id=None, delete_tn=False):
        logging.info(self.LOGNAME + "Send request to BWKS to delete User " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserDeleteRequest", req)
        response = self.__send_request(request)
        if delete_tn:
            self.GroupDnUnassignListRequest(ent_id, group_id, user_id)
            self.ServiceProviderDnDeleteListRequest(ent_id, user_id)
        return response

    def UserThirdPartyVoiceMailSupportGetRequest17(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get User's 3PVM settings: " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserThirdPartyVoiceMailSupportGetRequest17", req)
        response = self.__send_request(request)

        return response

    def UserVoiceMessagingUserGetAdvancedVoiceManagementRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get User's Voice Management settings: " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserVoiceMessagingUserGetAdvancedVoiceManagementRequest", req)
        response = self.__send_request(request)

        return response

    def GroupAccessDeviceDeleteRequest(self, device_name, ent_id, group_id):
        logging.info(self.LOGNAME + "Send request to BWKS to delete group device " + device_name)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <deviceName>""" + device_name + """</deviceName>
      """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAccessDeviceDeleteRequest", req)
        response = self.__send_request(request)

        return response

    def UserSharedCallAppearanceDeleteEndpointListRequest14(self, user_id, device_name, line_port):
        logging.info(self.LOGNAME + "Send request to BWKS to delete User's SCA: " + device_name)
        reqst = """
        <userId>""" + user_id + """</userId>
        <accessDeviceEndpoint>
          <accessDevice>
            <deviceLevel>Group</deviceLevel>
            <deviceName>""" + device_name + """</deviceName>
          </accessDevice>
          <linePort>""" + line_port + """</linePort>
        </accessDeviceEndpoint>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserSharedCallAppearanceDeleteEndpointListRequest14", req)
        response = self.__send_request(request)

        return response

    def SystemAccessDeviceDeleteRequest(self, device_name):
        logging.info(self.LOGNAME + "Send request to BWKS to delete group device " + device_name)
        reqst = """
        <deviceName>""" + device_name + """</deviceName>
      """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemAccessDeviceDeleteRequest", req)
        response = self.__send_request(request)

        return response

   

    def SystemAccessDeviceTypeDeleteRequest(self, device_type):
        logging.info(self.LOGNAME + "Send request to BWKS to delete system device type " + device_type)
        reqst = """
        <deviceType>""" + device_type + """</deviceType>
      """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemSIPDeviceTypeDeleteRequest", req)
        response = self.__send_request(request)

        return response

    def ServiceProviderAccessDeviceDeleteRequest(self, device_name, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to delete group device " + device_name)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <deviceName>""" + device_name + """</deviceName>
      """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderAccessDeviceDeleteRequest", req)
        response = self.__send_request(request)

        return response

    def GroupNetworkClassOfServiceGetAssignedListRequest(self, ent_id, group_id):
        logging.info(self.LOGNAME + "Send request to get list of NCOS for group '%s:%s" % (ent_id, group_id))
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
                """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupNetworkClassOfServiceGetAssignedListRequest", req)
        response = self.__send_request(request)

        return response

    def ServiceProviderNetworkClassOfServiceGetAssignedListRequest(self, ent_id):
        logging.info(self.LOGNAME + "Send request to get list of NCOS for ent " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
                """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderNetworkClassOfServiceGetAssignedListRequest", req)
        response = self.__send_request(request)

        return response

    def UserPilotDeleteRequest(self, user_id, ent_id, group_id):
        logging.info(self.LOGNAME + "Send request to BWKS to delete User " + user_id)
        self.GroupTrunkGroupModifyInstanceRequest14sp4(ent_id, group_id, user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserDeleteRequest", req)
        response = self.__send_request(request)
        self.GroupDnUnassignListRequest(ent_id, group_id, user_id)
        self.ServiceProviderDnDeleteListRequest(ent_id, user_id)
        return response

    def GroupExtensionLengthModifyRequest17(self, ent_id, group_id, ext_data):
        logging.info(self.LOGNAME + "Send request to BWKS to Modify Extensions")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <minExtensionLength>""" + ext_data['min'] + """</minExtensionLength>
        <maxExtensionLength>""" + ext_data['max'] + """</maxExtensionLength>
        <defaultExtensionLength>""" + ext_data['def'] + """</defaultExtensionLength>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupExtensionLengthModifyRequest17", req)
        response = self.__send_request(request)
        return response


    def GroupTrunkGroupModifyRequest14sp9(self, ent_id, group_id, calls, bursting=None):
        logging.info(self.LOGNAME + "Send request to BWKS to Modify Extensions")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <maxActiveCalls>""" + calls + """</maxActiveCalls>
        """
        if bursting is not None:
            reqst += """<burstingMaxActiveCalls>
                          <quantity>""" + bursting + """</quantity>
                        </burstingMaxActiveCalls>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupTrunkGroupModifyRequest14sp9", req)
        response = self.__send_request(request)
        return response

    def GroupTrunkGroupAddInstanceRequest19sp1(self, ent_id, group_id, user_id, device_data=None):
        logging.info(self.LOGNAME + "Send request to BWKS to Add TG " + user_id)

        if device_data is not None:
            device_data = """<accessDevice><deviceLevel>""" + device_data['level'] + """</deviceLevel><deviceName>""" + \
                          device_data['name'] + """</deviceName></accessDevice>"""
        else:
            device_data = ''

        reqst = """
                <serviceProviderId>""" + ent_id + """</serviceProviderId>
		<groupId>""" + group_id + """</groupId>
		<name>""" + user_id + """</name>""" + device_data + """
		<maxActiveCalls>1</maxActiveCalls>
		<enableBursting>false</enableBursting>
		<capacityExceededTrapInitialCalls>0</capacityExceededTrapInitialCalls>
		<capacityExceededTrapOffsetCalls>0</capacityExceededTrapOffsetCalls>
		<invitationTimeout>8</invitationTimeout>
		<requireAuthentication>false</requireAuthentication>
		<allowTerminationToTrunkGroupIdentity>false</allowTerminationToTrunkGroupIdentity>
		<allowTerminationToDtgIdentity>false</allowTerminationToDtgIdentity>
		<includeTrunkGroupIdentity>false</includeTrunkGroupIdentity>
		<includeDtgIdentity>false</includeDtgIdentity>
		<includeTrunkGroupIdentityForNetworkCalls>false</includeTrunkGroupIdentityForNetworkCalls>
		<includeOtgIdentityForNetworkCalls>false</includeOtgIdentityForNetworkCalls>
		<enableNetworkAddressIdentity>false</enableNetworkAddressIdentity>
		<allowUnscreenedCalls>true</allowUnscreenedCalls>
		<allowUnscreenedEmergencyCalls>false</allowUnscreenedEmergencyCalls>
		<pilotUserCallingLineIdentityForExternalCallsPolicy>No Calls</pilotUserCallingLineIdentityForExternalCallsPolicy>
		<pilotUserChargeNumberPolicy>No Calls</pilotUserChargeNumberPolicy>
		<routeToPeeringDomain>false</routeToPeeringDomain>
		<prefixEnabled>false</prefixEnabled>
		<prefix>1234</prefix>
		<statefulReroutingEnabled>false</statefulReroutingEnabled>
		<sendContinuousOptionsMessage>false</sendContinuousOptionsMessage>
		<continuousOptionsSendingIntervalSeconds>30</continuousOptionsSendingIntervalSeconds>
		<failureOptionsSendingIntervalSeconds>10</failureOptionsSendingIntervalSeconds>
		<failureThresholdCounter>1</failureThresholdCounter>
		<successThresholdCounter>1</successThresholdCounter>
		<inviteFailureThresholdCounter>1</inviteFailureThresholdCounter>
		<inviteFailureThresholdWindowSeconds>30</inviteFailureThresholdWindowSeconds>
		<pilotUserCallingLineAssertedIdentityPolicy>Unscreened Originating Calls</pilotUserCallingLineAssertedIdentityPolicy>
		<useSystemCallingLineAssertedIdentityPolicy>true</useSystemCallingLineAssertedIdentityPolicy>
		<pilotUserCallOptimizationPolicy>Optimize For User Services</pilotUserCallOptimizationPolicy>
		<clidSourceForScreenedCallsPolicy>Profile Name Profile Number</clidSourceForScreenedCallsPolicy>
		<useSystemCLIDSourceForScreenedCallsPolicy>true</useSystemCLIDSourceForScreenedCallsPolicy>
		<userLookupPolicy>Basic</userLookupPolicy>
		<useSystemUserLookupPolicy>true</useSystemUserLookupPolicy>
		<pilotUserCallingLineIdentityForEmergencyCallsPolicy>No Calls</pilotUserCallingLineIdentityForEmergencyCallsPolicy>\n
                """

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupTrunkGroupAddInstanceRequest19sp1", req)
        response = self.__send_request(request)
        return response

    def GroupTrunkGroupModifyInstanceRequest14sp4(self, ent_id, group_id, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to Modify TG " + user_id)
        reqst = """
        <trunkGroupKey>
            <serviceProviderId>""" + ent_id + """</serviceProviderId>
            <groupId>""" + group_id + """</groupId>
            <name>""" + user_id + """</name>
        </trunkGroupKey>
        <pilotUserId xsi:nil="true"></pilotUserId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupTrunkGroupModifyInstanceRequest14sp4", req)
        response = self.__send_request(request)
        return response

    def GroupTrunkGroupGetInstanceListRequest(self, ent_id, group_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get list of TG in group" + group_id)
        reqst = """
            <serviceProviderId>""" + ent_id + """</serviceProviderId>
            <groupId>""" + group_id + """</groupId>
            """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupTrunkGroupGetInstanceListRequest14", req)
        response = self.__send_request(request)
        return response

    def GroupTrunkGroupDeleteInstanceRequest14sp4(self, ent_id, group_id, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to Delete TG " + user_id)
        reqst = """
        <trunkGroupKey>
            <serviceProviderId>""" + ent_id + """</serviceProviderId>
            <groupId>""" + group_id + """</groupId>
            <name>""" + user_id + """</name>
        </trunkGroupKey>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupTrunkGroupDeleteInstanceRequest14sp4", req)
        response = self.__send_request(request)

        return response
    
    def GroupGroupPagingDeleteInstanceRequest(self,serviceusr_id):
        logging.info(self.LOGNAME + "Send request to BWKS to delete paging group"+serviceusr_id)
        reqst = """
        
            <serviceUserId>""" + serviceusr_id + """</serviceUserId>
            
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupGroupPagingDeleteInstanceRequest", req)
        response = self.__send_request(request)

        return response

    def GroupTrunkGroupUnassignPilotUser(self, ent_id, group_id, name):
        logging.info(self.LOGNAME + "Send request to BWKS to Unassign Pilot User from TG " + name)
        reqst = """
        <trunkGroupKey>
            <serviceProviderId>""" + ent_id + """</serviceProviderId>
            <groupId>""" + group_id + """</groupId>
            <name>""" + name + """</name>
        </trunkGroupKey>
        <pilotUserId xsi:nil="true"></pilotUserId>
        <trunkGroupIdentity xsi:nil="true"/>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupTrunkGroupModifyInstanceRequest15", req)
        response = self.__send_request(request)

        return response

    def GroupTrunkGroupGetInstanceUserListRequest(self, ent_id, group_id, name):
        logging.info(self.LOGNAME + "Send request to BWKS to Get Pilot User List from TG " + name)
        reqst = """
        <trunkGroupKey>
            <serviceProviderId>""" + ent_id + """</serviceProviderId>
            <groupId>""" + group_id + """</groupId>
            <name>""" + name + """</name>
        </trunkGroupKey>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupTrunkGroupGetInstanceUserListRequest14sp4", req)
        response = self.__send_request(request)

        return response



    def GroupHuntGroupDeleteInstanceRequest(self, user_id, ent_id="", group_id="", delete_tn=False):
        logging.info(self.LOGNAME + "Send request to BWKS to delete Hunt-Group: '" + user_id + "'")
        reqst = """
        <serviceUserId>""" + user_id + """</serviceUserId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupHuntGroupDeleteInstanceRequest", req)
        response = self.__send_request(request)
        if delete_tn:
            self.GroupDnUnassignListRequest(ent_id, group_id, user_id)
            self.ServiceProviderDnDeleteListRequest(ent_id, user_id)
        return response
    
    def GroupBroadWorksAnywhereDeleteInstanceRequest(self, user_id, ent_id="", group_id="", delete_tn=False):
        logging.info(self.LOGNAME + "Send request to BWKS to delete Broadworks Anywhere: '" + user_id + "'")
        reqst = """
        <serviceUserId>""" + user_id + """</serviceUserId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupBroadWorksAnywhereDeleteInstanceRequest", req)
        response = self.__send_request(request)
        if delete_tn:
            self.GroupDnUnassignListRequest(ent_id, group_id, user_id)
            self.ServiceProviderDnDeleteListRequest(ent_id, user_id)
        return response

    # Bad request. Should be refactored.
    def GroupVuserModifyInstanceRequest(self, vuser_type, vuser, phone):
        request_dict = {"Auto Attendant": "GroupAutoAttendantModifyInstanceRequest17sp1",
                        "Call Center": "GroupCallCenterModifyInstanceRequest19",
                        "Hunt Group": "GroupHuntGroupModifyInstanceRequest",
                        "Instant Group Call": "GroupInstantGroupCallModifyInstanceRequest"}
        logging.info(self.LOGNAME + "Send request to BWKS to Modify " + vuser_type + " " + vuser.entity_id)
        if phone != "":
            reqst = """
            <serviceUserId>""" + vuser.entity_id + """</serviceUserId>
            <serviceInstanceProfile>
                <phoneNumber>""" + phone + """</phoneNumber>
                <extension>""" + phone[-4:] + """</extension>
                <sipAliasList xsi:nil="true"/>
                <publicUserIdentity xsi:nil="true"/>
            </serviceInstanceProfile>
            """
        else:
            reqst = """
            <serviceUserId>""" + vuser.entity_id + """</serviceUserId>
            <serviceInstanceProfile>
                <phoneNumber xsi:nil="true"/>
                <extension xsi:nil="true"/>
                <sipAliasList xsi:nil="true"/>
                <publicUserIdentity xsi:nil="true"/>
            </serviceInstanceProfile>
            """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body(request_dict[vuser_type], req)
        response = self.__send_request(request)
        return response

    # generic method for vuser deletion
    def GroupVUserDeleteInstanceRequest(self, vuser_data):
        reqst = """
        <serviceUserId>""" + vuser_data['vuser_id'] + """</serviceUserId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        # selecting right request head for request
        # string slices are used here because CC & AA options can be given here with type, (e.g "Auto Attendant - Standard")
        if vuser_data['vuser_type'][:11] == "Call Center":
            logging.info(self.LOGNAME + "Send request to BWKS to Delete Call Center: " + vuser_data['vuser_id'])
            rqst = "GroupCallCenterDeleteInstanceRequest"
        elif vuser_data['vuser_type'][:14] == "Auto Attendant":
            logging.info(self.LOGNAME + "Send request to BWKS to Delete Auto Attendant: " + vuser_data['vuser_id'])
            rqst = "GroupAutoAttendantDeleteInstanceRequest"
        elif vuser_data['vuser_type'] == "Hunt Group":
            logging.info(self.LOGNAME + "Send request to BWKS to Delete Hunt Group: " + vuser_data['vuser_id'])
            rqst = "GroupHuntGroupDeleteInstanceRequest"
        elif vuser_data['vuser_type'] == "Instant Group Call":
            logging.info(self.LOGNAME + "Send request to BWKS to Delete Instant Group Call: " + vuser_data['vuser_id'])
            rqst = "GroupInstantGroupCallDeleteInstanceRequest"
        elif vuser_data['vuser_type'] == "BroadWorks Anywhere":
            logging.info(self.LOGNAME + "Send request to BWKS to Delete BroadWorks Anywhere: " + vuser_data['vuser_id'])
            rqst = "GroupBroadWorksAnywhereDeleteInstanceRequest"
        elif vuser_data['vuser_type'][:7] == "Meet Me":
            logging.info(
                self.LOGNAME + "Send request to BWKS to Delete Meet-me conferencing: " + vuser_data['vuser_id'])
            rqst = "GroupMeetMeConferencingDeleteInstanceRequest"
        elif vuser_data['vuser_type'] == "Group Paging":
            logging.info(self.LOGNAME + "Send request to BWKS to Delete Group Paging: " + vuser_data['vuser_id'])
            rqst = "GroupGroupPagingDeleteInstanceRequest"
        else:
            logging.info(self.LOGNAME + vuser_data['vuser_type'] + " :this type of vuser is not supported yet")
            return
        request = self._generate_request_body(rqst, req)
        response = self.__send_request(request)
        if 'phone' in vuser_data and vuser_data['phone'] != "" and vuser_data['phone'] is not None:
            self.GroupDnUnassignListRequest(vuser_data['ent_id'], vuser_data['grp_id'], vuser_data['phone'])
            self.ServiceProviderDnDeleteListRequest(vuser_data['ent_id'], vuser_data['phone'])
        return response

    def GroupInstantGroupCallDeleteInstanceRequest(self, igc_data):
        logging.info(self.LOGNAME + "Send request to BWKS to Delete Instant Group Call " + igc_data['igc_id'])
        reqst = """
        <serviceUserId>""" + igc_data['igc_id'] + """</serviceUserId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupInstantGroupCallDeleteInstanceRequest", req)
        response = self.__send_request(request)
        # if igc_data['phone'] != "" or igc_data['phone'] is not None: # doesn't work for None: evaluates to true
        if 'phone' in igc_data and igc_data['phone'] != "" and igc_data['phone'] is not None:
            self.GroupDnUnassignListRequest(igc_data['ent_id'], igc_data['grp_id'], igc_data['phone'])
            self.ServiceProviderDnDeleteListRequest(igc_data['ent_id'], igc_data['phone'])
        return response





    def GroupCallCenterGetAgentListRequest(self, cc_id):
        logging.info(self.LOGNAME + "Send request to BWKS to Get Call Center Agents " + cc_id)
        reqst = """
        <serviceUserId>""" + cc_id + """</serviceUserId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallCenterGetAgentListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupCallCenterGetAvailableAgentListRequest(self, ent_id, grp_id, cc_type):
        logging.info(self.LOGNAME + "Send request to BWKS to Get Call Center available Agents for cc type: " + cc_type)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        <callCenterType>""" + cc_type + """</callCenterType>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallCenterGetAvailableAgentListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupMeetMeConferencingModifyInstanceRequest(self, mmc_id, ports='unlimited'):
        logging.info(self.LOGNAME + "Send request to BWKS to Modify Meet-me conferencing " + mmc_id)
        reqst = """
        <serviceUserId>""" + mmc_id + """</serviceUserId>
        <allocatedPorts>
          """
        if ports == 'unlimited':
            reqst += """<unlimited>true</unlimited>
        </allocatedPorts>"""
        else:
            reqst += """<quantity>""" + str(ports) + """</quantity>
        </allocatedPorts>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupMeetMeConferencingModifyInstanceRequest", req)
        response = self.__send_request(request)
        return response

    # Method for adding AA
    # types can be "Standard" or "Basic";
    # extensionDialingScope & nameDialingScope - "Enterprise", "Group", or "Department";
    # nameDialingEntries - "LastName + FirstName" or "LastName + FirstName or FirstName + LastName" (whatever it means).
    # ...
    # Please, note that aa_id should contain @host part, it is not added here in the method
    def GroupAutoAttendantAddInstanceRequest19(self, ent_id, group_id, aa_id, aa_name, aa_type="Standard",
                                               enableVideo="false", extensionDialingScope="Group",
                                               nameDialingScope="Group", nameDialingEntries="LastName + FirstName"):
        logging.info(self.LOGNAME + "Send request to BWKS to add " + aa_type + " AutoAttendant: " + aa_name)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <serviceUserId>""" + aa_id + """</serviceUserId>
            <serviceInstanceProfile>
                <name>""" + aa_name + """</name>
                <callingLineIdLastName>""" + aa_name + """</callingLineIdLastName>
                <callingLineIdFirstName>""" + aa_name + """</callingLineIdFirstName>
                <language>English</language>
                <timeZone>America/New_York</timeZone>
            </serviceInstanceProfile>
        <type>""" + aa_type + """</type>
        <enableVideo>""" + enableVideo + """</enableVideo>
        <extensionDialingScope>""" + extensionDialingScope + """</extensionDialingScope>
        <nameDialingScope>""" + nameDialingScope + """</nameDialingScope>
        <nameDialingEntries>""" + nameDialingEntries + """</nameDialingEntries>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAutoAttendantAddInstanceRequest19", req)
        response = self.__send_request(request)
        return response


    def GroupAutoAttendantModifyInstanceRequest20(self, id, num):
        attendant_id = id
        attendant_num = num

        reqst = """
        <serviceUserId>""" + attendant_id + """</serviceUserId>
        <serviceInstanceProfile>
         <phoneNumber>""" + attendant_num + """</phoneNumber>
         <extension>""" + attendant_num[-4:] + """</extension>
         <sipAliasList xsi:nil="true"/>
         <publicUserIdentity xsi:nil="true"/>
        </serviceInstanceProfile>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAutoAttendantModifyInstanceRequest20", req)
        # print request
        response = self.__send_request(request)

        return response

    def GroupAutoAttendantAddInstanceRequest(self, ent_id, group_id, aa_data, country_code=""):
        logging.info(self.LOGNAME + "Send request to BWKS to add " + aa_data['aa_type'] + " AutoAttendant: " + aa_data[
            'aa_name'])
        if country_code == "":
            country_code= self._country_code
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <serviceUserId>""" + aa_data['aa_id'] + """</serviceUserId>
            <serviceInstanceProfile>
                <name>""" + aa_data['aa_name'] + """</name>
                <callingLineIdLastName>""" + aa_data['aa_lname'] + """</callingLineIdLastName>
                <callingLineIdFirstName>""" + aa_data['aa_fname'] + """</callingLineIdFirstName>
                <phoneNumber>""" + country_code + aa_data['aa_phone'] + """</phoneNumber>
                <extension>""" + aa_data['aa_ext'] + """</extension>
                <language>English</language>
                <timeZone>America/New_York</timeZone>
            </serviceInstanceProfile>
        <type>""" + aa_data['aa_type'] + """</type>
        <enableVideo>false</enableVideo>
        <extensionDialingScope>Enterprise</extensionDialingScope>
        <nameDialingScope>Enterprise</nameDialingScope>
        <nameDialingEntries>LastName + FirstName</nameDialingEntries>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAutoAttendantAddInstanceRequest19", req)
        response = self.__send_request(request)
        return response
    
    
    def GroupBroadWorksAnywhereAddInstanceRequest(self, ent_id, group_id, aa_data):
        logging.info(self.LOGNAME + "Send request to BWKS to add Broadworks Anywhere: " + aa_data['ba_name'])
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <serviceUserId>""" + aa_data['ba_id'] + """</serviceUserId>
            <serviceInstanceProfile>
                <name>""" + aa_data['ba_name'] + """</name>
                <callingLineIdLastName>""" + aa_data['ba_lname'] + """</callingLineIdLastName>
                <callingLineIdFirstName>""" + aa_data['ba_fname'] + """</callingLineIdFirstName>
                <phoneNumber>""" + self._country_code + aa_data['ba_phone'] + """</phoneNumber>
                <extension>""" + aa_data['ba_ext'] + """</extension>
                <language>English</language>
                <timeZone>America/New_York</timeZone>
            </serviceInstanceProfile>
        <broadWorksAnywhereScope>Group</broadWorksAnywhereScope>
        <promptForCLID>Prompt When Not Available</promptForCLID>
        <silentPromptMode>false</silentPromptMode>
        <promptForPasscode>false</promptForPasscode>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupBroadWorksAnywhereAddInstanceRequest", req)
        response = self.__send_request(request)
        return response

    def GroupRoutingProfileGetRequest(self, ent_id, group_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get routing profile: " )
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupRoutingProfileGetRequest", req)
        response = self.__send_request(request)
        return response
    
    def GroupRoutingProfileModifyRequest(self, ent_id, group_id,profile_name):
        logging.info(self.LOGNAME + "Send request to BWKS to get routing profile: " )
        if profile_name != "None":
           reqst = """
            <serviceProviderId>""" + ent_id + """</serviceProviderId>
            <groupId>""" + group_id + """</groupId>
            <routingProfile xsi:nil="true"></routingProfile>
            """
        else:
           reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <routingProfile>"""+profile_name+"""</routingProfile>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupRoutingProfileModifyRequest", req)
        response = self.__send_request(request)
        return response
    def GroupHuntGroupAddInstanceRequest19(self, ent_id, group_id, hg_id, hg_name):
        logging.info(self.LOGNAME + "Send request to BWKS to add  Hunt Group: " + hg_name)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <serviceUserId>""" + hg_id + """</serviceUserId>
            <serviceInstanceProfile>
                <name>""" + hg_name + """</name>
                <callingLineIdLastName>""" + hg_name + """</callingLineIdLastName>
                <callingLineIdFirstName>""" + hg_name + """</callingLineIdFirstName>
                <language>English</language>
                <timeZone>America/New_York</timeZone>
            </serviceInstanceProfile>
        <policy>Circular</policy>
        <huntAfterNoAnswer>false</huntAfterNoAnswer>
        <noAnswerNumberOfRings>1</noAnswerNumberOfRings>
        <forwardAfterTimeout>false</forwardAfterTimeout>
        <forwardTimeoutSeconds>30</forwardTimeoutSeconds>
        <allowCallWaitingForAgents>false</allowCallWaitingForAgents>
        <useSystemHuntGroupCLIDSetting>true</useSystemHuntGroupCLIDSetting>
        <includeHuntGroupNameInCLID>true</includeHuntGroupNameInCLID>
        <enableNotReachableForwarding>false</enableNotReachableForwarding>
        <makeBusyWhenNotReachable>false</makeBusyWhenNotReachable>
        <allowMembersToControlGroupBusy>false</allowMembersToControlGroupBusy>
        <enableGroupBusy>false</enableGroupBusy>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupHuntGroupAddInstanceRequest19", req)
        response = self.__send_request(request)

        return response

    def GroupHuntGroupAddInstanceRequest(self, ent_id, group_id, hg_data):
        logging.info(self.LOGNAME + "Send request to BWKS to add  Hunt Group: " + hg_data['hg_name'])
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <serviceUserId>""" + hg_data['hg_id'] + """</serviceUserId>
            <serviceInstanceProfile>
                <name>""" + hg_data['hg_name'] + """</name>
                <callingLineIdLastName>""" + hg_data['hg_lname'] + """</callingLineIdLastName>
                <callingLineIdFirstName>""" + hg_data['hg_fname'] + """</callingLineIdFirstName>
                <phoneNumber>""" + self._country_code + hg_data['hg_phone'] + """</phoneNumber>
				<extension>""" + hg_data['hg_ext'] + """</extension>
                <language>English</language>
                <timeZone>America/New_York</timeZone>
            </serviceInstanceProfile>
        <policy>Circular</policy>
        <huntAfterNoAnswer>false</huntAfterNoAnswer>
        <noAnswerNumberOfRings>1</noAnswerNumberOfRings>
        <forwardAfterTimeout>false</forwardAfterTimeout>
        <forwardTimeoutSeconds>30</forwardTimeoutSeconds>
        <allowCallWaitingForAgents>false</allowCallWaitingForAgents>
        <useSystemHuntGroupCLIDSetting>true</useSystemHuntGroupCLIDSetting>
        <includeHuntGroupNameInCLID>true</includeHuntGroupNameInCLID>
        <enableNotReachableForwarding>false</enableNotReachableForwarding>
        <makeBusyWhenNotReachable>false</makeBusyWhenNotReachable>
        <allowMembersToControlGroupBusy>false</allowMembersToControlGroupBusy>
        <enableGroupBusy>false</enableGroupBusy>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupHuntGroupAddInstanceRequest19", req)
        response = self.__send_request(request)

        return response
    
    def GroupCollaborateBridgeAddInstanceRequest(self, ent_id, group_id, cb_data):
        logging.info(self.LOGNAME + "Send request to BWKS to add  Collaborate bridge: " + cb_data['serviceUserId'])
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <serviceUserId>""" + cb_data['serviceUserId'] + """</serviceUserId>
        <serviceInstanceProfile>
            <name>""" + cb_data['name'] + """</name>
            <callingLineIdLastName>""" + cb_data['callingLineIdLastName'] + """</callingLineIdLastName>
            <callingLineIdFirstName>""" + cb_data['callingLineIdFirstName'] + """</callingLineIdFirstName>
            <phoneNumber>""" + self._country_code + cb_data['phoneNumber'] + """</phoneNumber>
            <extension>""" + cb_data['extension'] + """</extension>
        </serviceInstanceProfile>
        <maximumBridgeParticipants>
            <quantity>3</quantity>
        </maximumBridgeParticipants>
        <maxCollaborateRoomParticipants>15</maxCollaborateRoomParticipants>
        <supportOutdial>false</supportOutdial>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCollaborateBridgeAddInstanceRequest", req)
        response = self.__send_request(request)

        return response
    
    def GroupCollaborateBridgeAddInstanceRequest2(self, ent_id, group_id, cb_data):
        logging.info(self.LOGNAME + "Send request to BWKS to add  Collaborate bridge: " + cb_data['serviceUserId'])
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <serviceUserId>""" + cb_data['serviceUserId'] + """</serviceUserId>
        <serviceInstanceProfile>
            <name>""" + cb_data['name'] + """</name>
            <callingLineIdLastName>""" + cb_data['callingLineIdLastName'] + """</callingLineIdLastName>
            <callingLineIdFirstName>""" + cb_data['callingLineIdFirstName'] + """</callingLineIdFirstName>
        </serviceInstanceProfile>
        <maximumBridgeParticipants>
            <quantity>3</quantity>
        </maximumBridgeParticipants>
        <maxCollaborateRoomParticipants>15</maxCollaborateRoomParticipants>
        <supportOutdial>false</supportOutdial>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCollaborateBridgeAddInstanceRequest", req)
        response = self.__send_request(request)

        return response

    def GroupInstantGroupCallAddInstanceRequest14(self, ent_id, group_id, igc_id, igc_name):
        logging.info(self.LOGNAME + "Send request to BWKS to add  Instant Group Call: " + igc_name)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <serviceUserId>""" + igc_id + """</serviceUserId>
            <serviceInstanceProfile>
                <name>""" + igc_name + """</name>
                <callingLineIdLastName>""" + igc_name + """</callingLineIdLastName>
                <callingLineIdFirstName>""" + igc_name + """</callingLineIdFirstName>
                <language>English</language>
                <timeZone>America/New_York</timeZone>
            </serviceInstanceProfile>
        <isAnswerTimeoutEnabled>false</isAnswerTimeoutEnabled>
        <answerTimeoutMinutes>1</answerTimeoutMinutes>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupInstantGroupCallAddInstanceRequest14", req)
        response = self.__send_request(request)
        return response

    def GroupInstantGroupCallAddInstanceRequest(self, ent_id, group_id, igc_data):
        logging.info(self.LOGNAME + "Send request to BWKS to add  Instant Group Call: " + igc_data['igc_name'])
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <serviceUserId>""" + igc_data['igc_id'] + """</serviceUserId>
            <serviceInstanceProfile>
                <name>""" + igc_data['igc_name'] + """</name>
                <callingLineIdLastName>""" + igc_data['igc_lname'] + """</callingLineIdLastName>
                <callingLineIdFirstName>""" + igc_data['igc_fname'] + """</callingLineIdFirstName>
                <phoneNumber>""" + self._country_code + igc_data['igc_phone'] + """</phoneNumber>
				<extension>""" + igc_data['igc_ext'] + """</extension>
                <language>English</language>
                <timeZone>America/New_York</timeZone>
            </serviceInstanceProfile>
        <isAnswerTimeoutEnabled>false</isAnswerTimeoutEnabled>
        <answerTimeoutMinutes>1</answerTimeoutMinutes>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupInstantGroupCallAddInstanceRequest14", req)
        response = self.__send_request(request)
        return response

    def GroupCallCenterAddInstanceRequest19(self, ent_id, group_id, cc_id, cc_name, cc_type='Basic'):
        logging.info(self.LOGNAME + "Send request to BWKS to add Call Center: " + cc_name)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <serviceUserId>""" + cc_id + """</serviceUserId>
            <serviceInstanceProfile>
                <name>""" + cc_name + """</name>
                <callingLineIdLastName>""" + cc_name + """</callingLineIdLastName>
                <callingLineIdFirstName>""" + cc_name + """</callingLineIdFirstName>
                <password>Qwerty!123</password>
            </serviceInstanceProfile>
        <type>""" + cc_type + """</type>
        """

        if cc_type == 'Premium':
            reqst += "<routingType>Priority Based</routingType>"

        reqst += """<policy>Regular</policy>
        <enableVideo>false</enableVideo>
        <queueLength>0</queueLength>
        """
        if cc_type in ['Standard', 'Premium']:
            reqst += "<enableReporting>false</enableReporting>"
        reqst += """<allowCallerToDialEscapeDigit>true</allowCallerToDialEscapeDigit>
        <escapeDigit>0</escapeDigit>
        <resetCallStatisticsUponEntryInQueue>false</resetCallStatisticsUponEntryInQueue>
        <allowAgentLogoff>false</allowAgentLogoff>
        <allowCallWaitingForAgents>false</allowCallWaitingForAgents>
        """
        if cc_type in ['Standard', 'Premium']:
            reqst += """<allowCallsToAgentsInWrapUp>false</allowCallsToAgentsInWrapUp>
        <overrideAgentWrapUpTime>false</overrideAgentWrapUpTime>
        """

        if cc_type == 'Premium':
            reqst += "<forceDeliveryOfCalls>false</forceDeliveryOfCalls>"

        if cc_type in ['Standard', 'Premium']:
            reqst += """<enableAutomaticStateChangeForAgents>false</enableAutomaticStateChangeForAgents>
            <agentStateAfterCall>Available</agentStateAfterCall>
            """

        reqst += """<externalPreferredAudioCodec>None</externalPreferredAudioCodec>
        <internalPreferredAudioCodec>None</internalPreferredAudioCodec>
        <playRingingWhenOfferingCall>true</playRingingWhenOfferingCall>
        """

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallCenterAddInstanceRequest19", req)
        response = self.__send_request(request)
        return response

    def GroupCallCenterAddInstanceRequest(self, ent_id, group_id, cc_data):
        logging.info(self.LOGNAME + "Send request to BWKS to add Call Center: " + cc_data['cc_id'])
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <serviceUserId>""" + cc_data['cc_id'] + """</serviceUserId>
            <serviceInstanceProfile>
                <name>""" + cc_data['cc_name'] + """</name>
                <callingLineIdLastName>""" + cc_data['cc_lname'] + """</callingLineIdLastName>
                <callingLineIdFirstName>""" + cc_data['cc_fname'] + """</callingLineIdFirstName>
                <phoneNumber>""" + self._country_code + cc_data['cc_phone'] + """</phoneNumber>
				<extension>""" + cc_data['cc_ext'] + """</extension>
                <password>Qwerty!123</password>
            </serviceInstanceProfile>
        <type>""" + cc_data['cc_type'] + """</type>
        """

        if cc_data['cc_type'] == 'Premium':
            reqst += "<routingType>Priority Based</routingType>"

        reqst += """<policy>Regular</policy>
        <enableVideo>false</enableVideo>
        <queueLength>0</queueLength>
        """
        if cc_data['cc_type'] in ['Standard', 'Premium']:
            reqst += "<enableReporting>false</enableReporting>"
        reqst += """<allowCallerToDialEscapeDigit>true</allowCallerToDialEscapeDigit>
        <escapeDigit>0</escapeDigit>
        <resetCallStatisticsUponEntryInQueue>false</resetCallStatisticsUponEntryInQueue>
        <allowAgentLogoff>false</allowAgentLogoff>
        <allowCallWaitingForAgents>false</allowCallWaitingForAgents>
        """
        if cc_data['cc_type'] in ['Standard', 'Premium']:
            reqst += """<allowCallsToAgentsInWrapUp>false</allowCallsToAgentsInWrapUp>
        <overrideAgentWrapUpTime>false</overrideAgentWrapUpTime>
        """

        if cc_data['cc_type'] == 'Premium':
            reqst += "<forceDeliveryOfCalls>false</forceDeliveryOfCalls>"

        if cc_data['cc_type'] in ['Standard', 'Premium']:
            reqst += """<enableAutomaticStateChangeForAgents>false</enableAutomaticStateChangeForAgents>
            """

        reqst += """<externalPreferredAudioCodec>None</externalPreferredAudioCodec>
        <internalPreferredAudioCodec>None</internalPreferredAudioCodec>
        <playRingingWhenOfferingCall>true</playRingingWhenOfferingCall>
        """
        ##        if cc_data['cc_type'] in ['Standard', 'Premium']:
        ##            reqst += """<networkClassOfService>MIA NCOS</networkClassOfService>
        ##        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallCenterAddInstanceRequest19", req)
        response = self.__send_request(request)
        return response

    def GroupAutoAttendantModifyInstanceRequest(self, aa_id, dict_1={}):
        logging.info(self.LOGNAME + "Send request to BWKS to Modify Auto-Attendant: " + aa_id)
        # Define default values for request
        dict_2 = {}
        dict_2['department'] = {}
        dict_2['department']['name'] = None
        dict_2['businessHours'] = {}
        dict_2['businessHours']['name'] = None
        # Let`s merge two dictionaries to the third which will be used in request
        if dict_1:
            user_data = dict_2.copy()
            user_data.update(dict_1)
        else:  # Use default values
            user_data = dict_2
        reqst = """
        <serviceUserId>""" + aa_id + """</serviceUserId>
        <serviceInstanceProfile>
          """
        if not user_data['department']['name']:
            reqst += """<department xsi:type="GroupDepartmentKey" xsi:nil="true"/>
        """
        else:
            reqst += """<department xsi:type="GroupDepartmentKey">
            <serviceProviderId>""" + user_data['department']['serviceProviderId'] + """</serviceProviderId>
            <groupId>""" + user_data['department']['groupId'] + """</groupId>
            <name>""" + user_data['department']['name'] + """</name>
          </department>
        """
        reqst += """</serviceInstanceProfile>
        """
        if not user_data['businessHours']['name']:
            reqst += """<businessHours xsi:nil="true"/>
        """
        else:
            reqst += """ <businessHours>
          <type>""" + user_data['businessHours']['type'] + """</type>
          <name>""" + user_data['businessHours']['name'] + """</name>
        </businessHours>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        response = self.__send_request(request)
        return response

    def GroupCallCenterModifyInstanceRequest19(self, cc_id, dict_1={}):
        logging.info(self.LOGNAME + "Send request to BWKS to Modify Call Center: " + cc_id)
        # Define default values for request
        dict_2 = {}
        dict_2['department'] = {}
        dict_2['department']['name'] = None
        # Let`s merge two dictionaries to the third which will be used in request
        if dict_1:
            user_data = dict_2.copy()
            user_data.update(dict_1)
        else:  # Use default values
            user_data = dict_2
        reqst = """
        <serviceUserId>""" + cc_id + """</serviceUserId>
        <serviceInstanceProfile>
          """
        if not user_data['department']['name']:
            reqst += """<department xsi:type="GroupDepartmentKey" xsi:nil="true"/>
        """
        else:
            reqst += """<department xsi:type="GroupDepartmentKey">
            <serviceProviderId>""" + user_data['department']['serviceProviderId'] + """</serviceProviderId>
            <groupId>""" + user_data['department']['groupId'] + """</groupId>
            <name>""" + user_data['department']['name'] + """</name>
          </department>
        """
        reqst += """</serviceInstanceProfile>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallCenterModifyInstanceRequest19", req)
        response = self.__send_request(request)
        return response

    def GroupMeetMeConferencingModifyRequest(self, ent_id, group_id, ports='unlimited'):
        logging.info(
            self.LOGNAME + "Send request to BWKS to Modify Group Meet-me conferencing setting from group " + group_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <allocatedPorts>
          """
        if ports == 'unlimited':
            reqst += """<unlimited>true</unlimited>
        </allocatedPorts>"""
        else:
            reqst += """<quantity>""" + str(ports) + """</quantity>
        </allocatedPorts>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupMeetMeConferencingModifyRequest", req)
        response = self.__send_request(request)
        return response

    def GroupMeetMeConferencingDeleteInstanceRequest(self, mmc_data):
        logging.info(self.LOGNAME + "Send request to BWKS to Delete Meet-Me Conferencing Call " + mmc_data['mmc_id'])
        reqst = """
        <serviceUserId>""" + mmc_data['mmc_id'] + """</serviceUserId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupMeetMeConferencingDeleteInstanceRequest", req)
        response = self.__send_request(request)
        # if mmc_data['phone_number'] != "" or mmc_data['phone_number'] is not None: # doesn't work for None: evaluates to true
        if 'phone_number' in mmc_data and mmc_data['phone_number'] != "" and mmc_data['phone_number'] is not None:
            self.GroupDnUnassignListRequest(mmc_data['ent_id'], mmc_data['grp_id'], mmc_data['phone_number'])
            self.ServiceProviderDnDeleteListRequest(mmc_data['ent_id'], mmc_data['phone_number'])
        return response

    def ServiceProviderAuthorizationServiceModifyRequestLists(self, ent_id, grp_services=[], user_services=[]):
        logging.info(self.LOGNAME + "Send request to BWKS to Modify Auth Service limit from enterprise " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>"""
        if grp_services:
            for grp_service in grp_services:
                reqst += """<groupServiceAuthorization>
                                <serviceName>""" + grp_service + """</serviceName>
                                <authorizedQuantity>
                                    <unlimited>true</unlimited>
                                </authorizedQuantity>
                            </groupServiceAuthorization>"""
        if user_services:
            for user_service in user_services:
                reqst += """<userServiceAuthorization>
                                <serviceName>""" + user_service + """</serviceName>
                                <authorizedQuantity>
                                    <unlimited>true</unlimited>
                                </authorizedQuantity>
                            </userServiceAuthorization>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderServiceModifyAuthorizationListRequest", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderMeetMeConferencingModifyRequest(self, ent_id, ports='unlimited'):
        logging.info(
            self.LOGNAME + "Send request to BWKS to Modify Group Meet-me conferencing setting from enterprise " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <allocatedPorts>
          """
        if ports == 'unlimited':
            reqst += """<unlimited>true</unlimited>
        </allocatedPorts>"""
        else:
            reqst += """<quantity>""" + str(ports) + """</quantity>
        </allocatedPorts>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderMeetMeConferencingModifyRequest", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderAuthorizationServiceModifyRequest(self, auth_pattern):
        logging.info(
            self.LOGNAME + "Send request to BWKS to Modify Auth Service limit from enterprise " + auth_pattern.ent_id)
        reqst = """
        <serviceProviderId>""" + auth_pattern.ent_id + """</serviceProviderId>""" + auth_pattern.get_service_auth_section()
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderServiceModifyAuthorizationListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupAuthorizationServiceModifyRequest(self, auth_pattern):
        logging.info(
            self.LOGNAME + "Send request to BWKS to Modify Auth Service limit from enterprise " + auth_pattern.ent_id)
        reqst = """
        <serviceProviderId>""" + auth_pattern.ent_id + """</serviceProviderId>""" + auth_pattern.get_group_level_section() + auth_pattern.get_service_auth_section()
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupServiceModifyAuthorizationListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupMeetMeConferencingAddInstanceRequest19(self, ent_id, group_id, service_id, host=""):
        logging.info(
            self.LOGNAME + "Send request to BWKS to Add Meet-me conferencing: " + service_id + "to group: " + ent_id + ":" + group_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <serviceUserId>""" + service_id + host + """</serviceUserId>
        <serviceInstanceProfile>
          <name>""" + service_id + """</name>
          <callingLineIdLastName>""" + service_id + """</callingLineIdLastName>
          <callingLineIdFirstName>""" + service_id + """</callingLineIdFirstName>
          <language>English</language>
          <timeZone>America/New_York</timeZone>
        </serviceInstanceProfile>
        <allocatedPorts>
          <unlimited>true</unlimited>
        </allocatedPorts>
        <securityPinLength>6</securityPinLength>
        <allowIndividualOutDial>true</allowIndividualOutDial>
        <conferenceHostUserId>8312155506@voip17sp4.demo.net</conferenceHostUserId>
        <conferenceHostUserId>8312155505@voip17sp4.demo.net</conferenceHostUserId>
        <playWarningPrompt>false</playWarningPrompt>
        <conferenceEndWarningPromptMinutes>10</conferenceEndWarningPromptMinutes>
        <enableMaxConferenceDuration>false</enableMaxConferenceDuration>
        <maxConferenceDurationMinutes>
          <hours>3</hours>
          <minutes>0</minutes>
        </maxConferenceDurationMinutes>
        <maxScheduledConferenceDurationMinutes>
          <hours>23</hours>
          <minutes>45</minutes>
        </maxScheduledConferenceDurationMinutes>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupMeetMeConferencingAddInstanceRequest19", req)
        response = self.__send_request(request)
        return response

    def UserMeetMeConferencingGetConferenceDelegateListRequest(self, user_id, meet_me_bridge, conf_id):
        logging.info(
            self.LOGNAME + "Send request to BWKS to GET List of Delegates for the conference: " + meet_me_bridge + ":" + conf_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        <conferenceKey>
          <bridgeId>""" + meet_me_bridge + """</bridgeId>
          <conferenceId>""" + conf_id + """</conferenceId>
        </conferenceKey>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserMeetMeConferencingGetConferenceDelegateListRequest", req)
        response = self.__send_request(request)
        return response

    def UserMeetMeConferencingAddConferenceRequest19(self, user_id, meet_me_bridge, title):
        logging.info(self.LOGNAME + "Send request to BWKS to add conference: " + meet_me_bridge + ":" + title)
        reqst = """
          <userId>""" + user_id + """</userId>
          <bridgeId>""" + meet_me_bridge + """</bridgeId>
          <title>""" + title + """</title>
          <restrictParticipants>false</restrictParticipants>
          <muteAllAttendeesOnEntry>0</muteAllAttendeesOnEntry>
          <endConferenceOnModeratorExit>0</endConferenceOnModeratorExit>
          <moderatorRequired>0</moderatorRequired>
          <requireSecurityPin>false</requireSecurityPin>
          <allowUniqueIdentifier>false</allowUniqueIdentifier>
          <attendeeNotification>Play Tone</attendeeNotification>
          <conferenceSchedule>
          <scheduleReservationless>
          <startTime>""" + datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d') + """T05:00:00+00:00</startTime>
          <endTime xsi:nil="true"/>
          </scheduleReservationless>
          </conferenceSchedule>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserMeetMeConferencingAddConferenceRequest19", req)
        response = self.__send_request(request)
        return response

    def UserGetRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to GET User " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserGetRequest19", req)
        response = self.__send_request(request)
        return response

    def UserGetRequest20(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to GET User " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserGetRequest20", req)
        response = self.__send_request(request)
        return response

    def UserAssignedServicesGetListRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to GET User " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserAssignedServicesGetListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupAutoAttendantSubmenuGetRequest(self, aa_id, submenu_name):
        logging.info(
            self.LOGNAME + "Send request to BWKS to GET info of Submenu " + submenu_name + ", Auto-Attendant: " + aa_id)
        reqst = """<serviceUserId>""" + aa_id + """</serviceUserId>
        <submenuId>""" + submenu_name + """</submenuId>
      """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAutoAttendantSubmenuGetRequest", req)
        response = self.__send_request(request)
        return response

    def GroupAutoAttendantSubmenuDeleteListRequest(self, aa_id, submenu_names=[]):
        reqst = """<serviceUserId>""" + aa_id + """</serviceUserId>
        """
        for submenu_name in submenu_names:
            reqst += """<submenuId>""" + submenu_name + """</submenuId>
        """
            logging.info(
                self.LOGNAME + "Send request to BWKS to DELETE Submenu " + submenu_name + ", Auto-Attendant: " + aa_id)
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAutoAttendantSubmenuDeleteListRequest", req)
        response = self.__send_request(request)
        return response
    
    def UserAnnouncementFileDeleteListRequest(self,user_id,name,filetype):
        logging.info(self.LOGNAME + "send req to delete announcement ")
        reqst = """
        <userId>""" + user_id + """</userId>
        <announcementFileKey>
        <name>""" + name + """</name>
        <mediaFileType>""" + filetype + """</mediaFileType>
         </announcementFileKey>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserAnnouncementFileDeleteListRequest", req)
        response = self.__send_request(request)
        return response
        

    def UserCallForwardingNotReachableGetRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to GET CallForwardingNotReachable service of User " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserCallForwardingNotReachableGetRequest", req)
        response = self.__send_request(request)
        return response

    def UserChargeNumberGetRequest14sp9(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to GET ChargeNumber service of User " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserChargeNumberGetRequest14sp9", req)
        response = self.__send_request(request)
        return response

    def UserSharedCallAppearanceGetRequest16sp2(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to GET SharedCallAppearance service of User " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserSharedCallAppearanceGetRequest16sp2", req)
        response = self.__send_request(request)
        return response

    def UserSharedCallAppearanceAddEndpointRequest14sp2(self, user_id, sca_line_data=None):
        logging.info(self.LOGNAME + "Send request to BWKS to Add SCA line to the user: " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        <accessDeviceEndpoint>
          <accessDevice>
            <deviceLevel>""" + sca_line_data['deviceLevel'] + """</deviceLevel>
            <deviceName>""" + sca_line_data['deviceName'] + """</deviceName>
          </accessDevice>
          <linePort>""" + sca_line_data['linePort'] + """</linePort>
        </accessDeviceEndpoint>
        <isActive>true</isActive>
        <allowOrigination>true</allowOrigination>
        <allowTermination>true</allowTermination>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserSharedCallAppearanceAddEndpointRequest14sp2", req)
        response = self.__send_request(request)
        return response

    def UserSharedCallAppearanceGetEndpointRequest(self, user_id, accessDeviceEndpoint, linePort):
        logging.info(self.LOGNAME + "Send request to BWKS to get SCA line to the user: " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        <accessDeviceEndpoint>
          <accessDevice>
            <deviceLevel>Group</deviceLevel>
            <deviceName>""" + accessDeviceEndpoint + """</deviceName>
          </accessDevice>
        <linePort>""" + linePort + """</linePort>
        </accessDeviceEndpoint>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserSharedCallAppearanceGetEndpointRequest", req)
        response = self.__send_request(request)
        return response

    def GroupSeriesCompletionGetInstanceRequest(self, ent_id, group_id, name):
        logging.info(self.LOGNAME + "Send request to BWKS to GET info of GroupSeriesCompletion with name: " + name)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <name>""" + name + """</name>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupSeriesCompletionGetInstanceRequest", req)
        response = self.__send_request(request)
        return response
    
 
    def GroupCollaborateBridgeGetInstanceListRequest(self, ent_id, group_id):
        logging.info(self.LOGNAME + "Send request to BWKS to GET info of GroupCollaborateBridgeGetInstanceListRequest")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCollaborateBridgeGetInstanceListRequest", req)
        response = self.__send_request(request)
        return response


    def GroupCallParkGetInstanceRequest(self, ent_id, group_id, name):
        logging.info(self.LOGNAME + "Send request to BWKS to GET info of Call Park with name: " + name)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <name>""" + name + """</name>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallParkGetInstanceRequest16sp2", req)
        response = self.__send_request(request)
        return response

    def GroupCallParkDeleteInstanceRequest(self, ent_id, gr_id, name):
        logging.info(self.LOGNAME + "Send request to BWKS to delete Call Park instance from Group: " + name)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + gr_id + """</groupId>
        <name>""" + name + """</name>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallParkDeleteInstanceRequest", req)
        response = self.__send_request(request)
        return response

    def GroupCallParkGetInstanceListRequest(self, ent_id, gr_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get list of Call Parks in group: " + ent_id + ":" + gr_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + gr_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallParkGetInstanceListRequest", req)
        response = self.__send_request(request)
        return response


    def GroupTrunkGroupGetInstanceRequest19(self, ent_id, group_id, name):
        logging.info(self.LOGNAME + "Send request to BWKS to GET info of Trunk Group Instance with name: " + name)
        reqst = """<trunkGroupKey>
          <serviceProviderId>""" + ent_id + """</serviceProviderId>
          <groupId>""" + group_id + """</groupId>
          <name>""" + name + """</name>
        </trunkGroupKey>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupTrunkGroupGetInstanceRequest19", req)
        response = self.__send_request(request)
        return response


    def GroupMeetMeConferencingGetInstanceRequest(self, bridge_id):
        logging.info(self.LOGNAME + "Send request to BWKS to GET info of Meet-Me conferencing with id: " + bridge_id)
        reqst = """
        <serviceUserId>""" + bridge_id + """</serviceUserId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupMeetMeConferencingGetInstanceRequest19", req)
        response = self.__send_request(request)
        return response

    def GroupSeriesCompletionGetInstanceListRequest(self, ent_id, group_id):
        logging.info(self.LOGNAME + "Send request to BWKS to GET list of series completion on group : " + group_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupSeriesCompletionGetInstanceListRequest", req)
        response = self.__send_request(request)
        return response

    def EnterpriseCallCenterGetRequest17sp4(self, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to GET Call Center settings of Enterprise:" + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("EnterpriseCallCenterGetRequest17sp4", req)
        response = self.__send_request(request)
        return response

    def EnterpriseCallCenterAgentUnavailableCodeSettingsGetRequest17sp4(self, ent_id):
        logging.info(
            self.LOGNAME + "Send request to BWKS to GET Call Center agent codes settings of Enterprise:" + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("EnterpriseCallCenterAgentUnavailableCodeSettingsGetRequest17sp4", req)
        response = self.__send_request(request)
        return response

    def EnterpriseCallCenterAgentUnavailableCodeGetListRequest(self, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to GET Call Center agent codes list of Enterprise:" + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("EnterpriseCallCenterAgentUnavailableCodeGetListRequest", req)
        response = self.__send_request(request)
        return response

    def EnterpriseCallCenterAgentUnavailableCodeAddRequest(self, ent_id, code, is_active, desc=""):
        logging.info(self.LOGNAME + "Send request to BWKS to Add Call Center code:" + code)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <isActive>""" + is_active + """</isActive>
        <code>""" + code + """</code>
        """
        if desc != "":
            reqst += """<description>""" + desc + """</description>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("EnterpriseCallCenterAgentUnavailableCodeAddRequest", req)
        response = self.__send_request(request)
        return response

    def GroupMusicOnHoldAddInstanceRequest16(self, ent_id, grp_id, department):
        logging.info(self.LOGNAME + "Send request to BWKS to Add Music on Hold")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        <department xsi:type="GroupDepartmentKey">
          <serviceProviderId>""" + ent_id + """</serviceProviderId>
          <groupId>""" + grp_id + """</groupId>
          <name>""" + department + """</name>
        </department>
        <isActiveDuringCallHold>false</isActiveDuringCallHold>
        <isActiveDuringCallPark>false</isActiveDuringCallPark>
        <isActiveDuringBusyCampOn>false</isActiveDuringBusyCampOn>
        <source>
          <audioFilePreferredCodec>None</audioFilePreferredCodec>
          <messageSourceSelection>System</messageSourceSelection>
        </source>
        <useAlternateSourceForInternalCalls>false</useAlternateSourceForInternalCalls>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupMusicOnHoldAddInstanceRequest16", req)
        response = self.__send_request(request)
        return response

    def GroupCallParkAddInstanceRequest16sp2(self, ent_id, grp_id, call_p):
        logging.info(self.LOGNAME + "Send request to BWKS to Add Call Park:" + call_p)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        <name>""" + call_p + """</name>
        <recallTo>Parking User Only</recallTo>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallParkAddInstanceRequest16sp2", req)
        response = self.__send_request(request)
        return response

    def GroupCallCapacityManagementAddInstanceRequest(self, ent_id, grp_id, call_p):
        logging.info(self.LOGNAME + "Send request to BWKS to Add Call Capacity:" + call_p)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        <name>""" + call_p + """</name>
        <maxActiveCallsAllowed>4</maxActiveCallsAllowed>
        <maxIncomingActiveCallsAllowed>1</maxIncomingActiveCallsAllowed>
        <maxOutgoingActiveCallsAllowed>1</maxOutgoingActiveCallsAllowed>
        <becomeDefaultGroupForNewUsers>false</becomeDefaultGroupForNewUsers>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallCapacityManagementAddInstanceRequest", req)
        response = self.__send_request(request)
        return response

    def GroupCallCenterAgentUnavailableCodeAddRequest(self, ent_id, grp_id, code, is_active, desc=""):
        logging.info(self.LOGNAME + "Send request to BWKS to Add Call Center code:" + code)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        <isActive>""" + is_active + """</isActive>
        <code>""" + code + """</code>
        """
        if desc != "":
            reqst += """<description>""" + desc + """</description>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallCenterAgentUnavailableCodeAddRequest", req)
        response = self.__send_request(request)
        return response

    def EnterpriseCallCenterAgentUnavailableCodeDeleteRequest(self, ent_id, code):
        logging.info(self.LOGNAME + "Send request to BWKS to Delete Call Center code:" + code)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <code>""" + code + """</code>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("EnterpriseCallCenterAgentUnavailableCodeDeleteRequest", req)
        response = self.__send_request(request)
        return response

    def EnterpriseCallCenterCallDispositionCodeGetListRequest(self, ent_id):
        logging.info(
            self.LOGNAME + "Send request to BWKS to GET Call Center agent disp codes list of Enterprise:" + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("EnterpriseCallCenterCallDispositionCodeGetListRequest", req)
        response = self.__send_request(request)
        return response

    def EnterpriseCallCenterCallDispositionCodeAddRequest(self, ent_id, code, is_active, desc=""):
        logging.info(self.LOGNAME + "Send request to BWKS to Add Call Center disp code:" + code)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <code>""" + code + """</code>
        <isActive>""" + is_active + """</isActive>
        """
        if desc != "":
            reqst += """<description>""" + desc + """</description>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("EnterpriseCallCenterCallDispositionCodeAddRequest", req)
        response = self.__send_request(request)
        return response

    def EnterpriseCallCenterCallDispositionCodeDeleteRequest(self, ent_id, code):
        logging.info(self.LOGNAME + "Send request to BWKS to Delete Call Center disp code:" + code)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <code>""" + code + """</code>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("EnterpriseCallCenterCallDispositionCodeDeleteRequest", req)
        response = self.__send_request(request)
        return response

    def EnterpriseCallCenterModifyRoutingPolicyRequest(self, ent_id, rp, call_centers, orders):
        logging.info(self.LOGNAME + "Send request to BWKS to GET Call Center Routing Policies of Enterprise:" + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <routingPolicy>""" + rp + """</routingPolicy>
        """
        for cc, order in zip(call_centers, orders):
            reqst += """<routingPriorityOrder>
                            <serviceUserId>""" + cc + """</serviceUserId>
                            <priority>""" + order + """</priority>
                        </routingPriorityOrder>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("EnterpriseCallCenterModifyRoutingPolicyRequest", req)
        response = self.__send_request(request)
        return response

    def EnterpriseCallCenterModifyRequest(self, ent_id, data):
        logging.info(self.LOGNAME + "Send request to BWKS to Modify Call Center settings of Enterprise:" + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <useSystemDefaultGuardTimer>""" + data['useSystemDefaultGuardTimer'] + """</useSystemDefaultGuardTimer>
        <enableGuardTimer>false</enableGuardTimer>
        <guardTimerSeconds>11</guardTimerSeconds>
        <useSystemDefaultUnavailableSettings>""" + data['useSystemDefaultUnavailableSettings'] + """</useSystemDefaultUnavailableSettings>
        <forceAgentUnavailableOnDNDActivation>false</forceAgentUnavailableOnDNDActivation>
        <forceAgentUnavailableOnPersonalCalls>false</forceAgentUnavailableOnPersonalCalls>
        <forceAgentUnavailableOnBouncedCallLimit>false</forceAgentUnavailableOnBouncedCallLimit>
        <numberConsecutiveBouncedCallsToForceAgentUnavailable>2</numberConsecutiveBouncedCallsToForceAgentUnavailable>
        <forceAgentUnavailableOnNotReachable>false</forceAgentUnavailableOnNotReachable>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("EnterpriseCallCenterModifyRequest", req)
        response = self.__send_request(request)
        return response

    def UserAuthenticationModifyRequest(self, user_id, user_name, user_password):
        logging.info(self.LOGNAME + "Send request to BWKS to SET Authentification service of User " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        <userName>""" + user_name + """</userName>
        <newPassword>""" + user_password + """ </newPassword>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserAuthenticationModifyRequest", req)
        response = self.__send_request(request)

        return response


    def UserAuthenticationGetRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to GET Authentification service of User " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserAuthenticationGetRequest", req)
        response = self.__send_request(request)

        return response

    def UserAlternateNumbersGetRequest17(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to GET Alternate numbers of User " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserAlternateNumbersGetRequest17", req)
        response = self.__send_request(request)

        return response
    
    def UserAlternateNumbersModifyRequest(self, user_id, tn, ext):
        logging.info(self.LOGNAME + "Send request to BWKS to GET Alternate numbers of User " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        <alternateEntry01><phoneNumber>"""+tn+"""</phoneNumber><extension>"""+ext+"""</extension><ringPattern>Long-Long</ringPattern></alternateEntry01>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserAlternateNumbersModifyRequest", req)
        response = self.__send_request(request)

        return response

    def UserServiceGetAssignmentListRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to GET list of assigned services of User " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserServiceGetAssignmentListRequest", req)
        response = self.__send_request(request)

        return response

    def UserSimultaneousRingPersonalModifyRequest17(self, user_id, number):
        logging.info(self.LOGNAME + "Send request to BWKS to modify Simul Ring Personal for User " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        <isActive>false</isActive>
        <doNotRingIfOnCall>true</doNotRingIfOnCall>
        <simultaneousRingNumberList>
          <simultaneousRingNumber>
            <phoneNumber>""" + number + """</phoneNumber>
            <answerConfirmationRequired>false</answerConfirmationRequired>
          </simultaneousRingNumber>
        </simultaneousRingNumberList>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserSimultaneousRingPersonalModifyRequest17", req)
        response = self.__send_request(request)
        return response

    def UserHotelingGuestModifyRequest(self, user_id, status):
        logging.info(self.LOGNAME + "Send request to BWKS to modify Hoteling Guest for User " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        <isActive>""" + status + """</isActive>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserHotelingGuestModifyRequest", req)
        response = self.__send_request(request)
        return response



    def UserAddRequest22(self,ent_id,grp_id,usr_id,usr_last,usr_first,usr_phone,usr_extn,usr_passwd ):
        logging.info(self.LOGNAME + "Send request to BWKS to add user " + usr_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        <userId>""" + usr_id + """</userId>
        <lastName>""" + usr_last + """</lastName>
        <firstName>""" + usr_first + """</firstName>
        <callingLineIdLastName>""" + usr_last + """</callingLineIdLastName>
        <callingLineIdFirstName>""" + usr_first + """</callingLineIdFirstName>
        <phoneNumber>""" + usr_phone + """</phoneNumber>
        <extension>""" + usr_extn + """</extension>
        <password>""" + usr_passwd + """</password>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserAddRequest22", req)
        response = self.__send_request(request)
        return response


    def UserAddRequest17sp4(self, ent_id, group_id, user_id, lname="Zauto", fname="User", phone_number="",
                            device_data=None, user_data={}):
        if phone_number != "":
            if "+" in phone_number:
                pn_data = phone_number.split("-")
                cc_code = pn_data[0]
                self.ServiceProviderDnAddListRequest(ent_id, pn_data[1], cc_code)
                self.GroupDnAssignListRequest(ent_id, group_id, pn_data[1], cc_code)
            else:
                self.ServiceProviderDnAddListRequest(ent_id, phone_number)
                self.GroupDnAssignListRequest(ent_id, group_id, phone_number)
        if device_data is not None:
            self.GroupAccessDeviceAddRequest14(ent_id, group_id, device_data)
            # self.GroupAccessDeviceCustomTagAddRequest(ent_id, group_id, device_data) #Maybe someone will need this :)
            # self.GroupCPEConfigRebuildDeviceConfigFileRequest(ent_id, group_id, device_data) #and this
        logging.info(self.LOGNAME + "Send request to BWKS to add User " + user_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <userId>""" + user_id + """</userId>
        <lastName>""" + lname + """</lastName>
        <firstName>""" + fname + """</firstName>
        """

        try:
            reqst += """<callingLineIdLastName>""" + user_data['callingLineIdLastName'] + """</callingLineIdLastName>
        """
        except KeyError:
            reqst += """<callingLineIdLastName>Auto</callingLineIdLastName>
        """
        try:
            reqst += """<callingLineIdFirstName>""" + user_data['callingLineIdFirstName'] + """</callingLineIdFirstName>
        """
        except KeyError:
            reqst += """<callingLineIdFirstName>User</callingLineIdFirstName>
        """
        # adding user w/o phone
        if phone_number != "":
            reqst += """
        <phoneNumber>""" + phone_number + """</phoneNumber>
        """
        try:
            reqst += """<extension>""" + user_data['extension'] + """</extension>
        """
        except KeyError:
            pass
        reqst += """
        <password>Leo2Loki4prom!!</password>
        """
        try:
            reqst += """<department xsi:type="GroupDepartmentKey">
                            <serviceProviderId> """ + ent_id + """ </serviceProviderId>
                            <groupId> """ +group_id + """ </groupId>
                            <name> """ + user_data['department'] + """ </name>
                        </department>
        """
        except KeyError:
            pass
        if device_data is not None:
            reqst += """
        <accessDeviceEndpoint>
          <accessDevice>
            <deviceLevel>Group</deviceLevel>
            <deviceName>""" + device_data['device_name'] + """</deviceName>
          </accessDevice>
          <linePort>""" + device_data['device_line_port'] + """</linePort>
          </accessDeviceEndpoint>
            """

        try:
            reqst += """<title>""" + user_data['title'] + """</title>
        """
        except KeyError:
            pass
        try:
            reqst += """<pagerPhoneNumber>""" + user_data['pagerPhoneNumber'] + """</pagerPhoneNumber>
        """
        except KeyError:
            pass
        try:
            reqst += """<emailAddress>""" + user_data['emailAddress'] + """</emailAddress>
        """
        except KeyError:
            pass
        try:
            reqst += """<yahooId>""" + user_data['yahooId'] + """</yahooId>
        """
        except KeyError:
            pass
        try:
            reqst += """<addressLocation>""" + user_data['addressLocation'] + """</addressLocation>
        """
        except KeyError:
            pass
        try:
            reqst += """<address>
          <addressLine1>""" + user_data['address']['addressLine1'] + """</addressLine1>
          <addressLine2>""" + user_data['address']['addressLine2'] + """</addressLine2>
          <city>""" + user_data['address']['city'] + """</city>
            <stateOrProvince>""" + user_data['address']['stateOrProvince'] + """</stateOrProvince>
          <zipOrPostalCode>""" + user_data['address']['zipOrPostalCode'] + """</zipOrPostalCode>
          <country>""" + user_data['address']['country'] + """</country>
        </address>
        """
        except KeyError:
            pass

        try:
            reqst += """<networkClassOfService>""" + user_data['networkClassOfService'] + """</networkClassOfService>
        """
        except KeyError:
            pass

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserAddRequest17sp4", req)
        response = self.__send_request(request)
        return response
    


    def GroupAccessDeviceModifyRequest14(self, device_data=None):
        logging.info(self.LOGNAME + "Send request to BWKS to Edit Device " + str(device_data['deviceName']))
        reqst = """
        <serviceProviderId>""" + device_data['serviceProviderId'] + """</serviceProviderId>
        <groupId>""" + device_data['groupId'] + """</groupId>
        <deviceName>""" + device_data['deviceName'] + """</deviceName>
        """
        try:
            if not device_data['macAddress']:
                reqst += """<macAddress xsi:nil="true"/>
        """
            else:
                reqst += """<macAddress>""" + device_data['macAddress'] + """</macAddress>
        """
        except KeyError:
            pass
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAccessDeviceModifyRequest14", req)
        response = self.__send_request(request)
        return response

    def GroupAccessDeviceModifyCredentials(self, device_data=None):
        logging.info(self.LOGNAME + "Send request to BWKS to Edit Device " + str(device_data['deviceName']))
        reqst = """
           <serviceProviderId>""" + device_data['serviceProviderId'] + """</serviceProviderId>
           <groupId>""" + device_data['groupId'] + """</groupId>
           <deviceName>""" + device_data['deviceName'] + """</deviceName>
           <configurationMode>Default</configurationMode>
           <useCustomUserNamePassword>true</useCustomUserNamePassword>
           <accessDeviceCredentials>
              <userName>""" + device_data['username'] + """</userName>
              <password>""" + device_data['password'] + """</password>
           </accessDeviceCredentials>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAccessDeviceModifyRequest14", req)
        response = self.__send_request(request)
        return response

    def GroupAccessDeviceGetRequest(self, device_data=None):
        logging.info(self.LOGNAME + "Send request to BWKS to retrive info of Device " + str(device_data['deviceName']))
        reqst = """
        <serviceProviderId>""" + device_data['serviceProviderId'] + """</serviceProviderId>
        <groupId>""" + device_data['groupId'] + """</groupId>
        <deviceName>""" + device_data['deviceName'] + """</deviceName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAccessDeviceGetRequest18sp1", req)
        response = self.__send_request(request)
        return response

    def UserCallProcessingGetPolicyRequest14sp7(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to GET UserCallProcessingGetPolicyRequest of User " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserCallProcessingGetPolicyRequest14sp7", req)
        response = self.__send_request(request)
        return response

    def UserGetListInGroupRequest(self, ent_id, grp_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve users in Group " + grp_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <GroupId>""" + grp_id + """</GroupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserGetListInGroupRequest", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderDnAddListRequest(self, ent_id, tn_range, ccode=None,phone_number=None):
        if ccode is None:
            ccode = self._country_code
        logging.info(self.LOGNAME + "Send request to BWKS to add phone number to the enterprise " + tn_range)
        if phone_number:
            reqst = """<serviceProviderId>""" + ent_id + """</serviceProviderId>
            <phoneNumber>"""+phone_number+"""</phoneNumber>
        """
        else:
            reqst = """<serviceProviderId>""" + ent_id + """</serviceProviderId>
        <dnRange>
            <minPhoneNumber>""" + ccode + tn_range + """</minPhoneNumber>
            <maxPhoneNumber>""" + ccode + tn_range + """</maxPhoneNumber>
        </dnRange>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderDnAddListRequest", req)
        response = self.__send_request(request)
        return response

    # It's possible to have several mobileSubscriberDirectoryNumber sections in this request
    # mobileNetworkName doesn't seems to be going to change in the near future

    def EnterpriseBroadWorksMobilityMobileSubscriberDirectoryNumberGetAssignmentListRequest(self, ent_id):
        logging.info(
            self.LOGNAME + "Send request to BWKS to  retrive Mobile phone numbers from the enterprise: '%s'" % ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body(
            "EnterpriseBroadWorksMobilityMobileSubscriberDirectoryNumberGetAssignmentListRequest", req)
        response = self.__send_request(request)
        return response

    def SystemAccessDeviceGetAllRequest(self, deviceType):
        logging.info(
            self.LOGNAME + "Send request to BWKS to retrieve all devices in the system with device type: '%s'" % deviceType)
        reqst = """
        <searchCriteriaExactDeviceType>
            <deviceType>""" + deviceType + """</deviceType>
        </searchCriteriaExactDeviceType>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemAccessDeviceGetAllRequest", req)
        response = self.__send_request(request)
        return response

    def SystemDeviceTypeGetAvailableListRequest19(self):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve all device types in the system")
        reqst = """
        <allowConference>true</allowConference>
        <allowMusicOnHold>true</allowMusicOnHold>
        <onlyConference>false</onlyConference>
        <onlyVideoCapable>false</onlyVideoCapable>
        <onlyOptionalIpAddress>false</onlyOptionalIpAddress>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemDeviceTypeGetAvailableListRequest19", req)
        response = self.__send_request(request)
        return response

    # It's possible to have several mobileSubscriberDirectoryNumber sections in this request
    # mobileNetworkName doesn't seems to be going to change in the near future
    def ServiceProviderBroadWorksMobilityMobileSubscriberDirectoryNumberDeleteListRequest(self, ent_id, mobile_number):
        logging.info(self.LOGNAME + "Send request to BWKS to delete BWKS Mobility number " + mobile_number)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <mobileSubscriberDirectoryNumber>""" + self._country_code + mobile_number + """</mobileSubscriberDirectoryNumber>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body(
            "ServiceProviderBroadWorksMobilityMobileSubscriberDirectoryNumberDeleteListRequest", req)
        response = self.__send_request(request)
        return response

    def UserBroadWorksMobilityModifyRequest(self, user_id, mobile_number):
        logging.info(
            self.LOGNAME + "Send request to BWKS to add a mobile identity " + mobile_number + "  to the user " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        <isActive>false</isActive>
        <phonesToRing>Fixed</phonesToRing>
        <mobilePhoneNumber>""" + mobile_number + """</mobilePhoneNumber>
        <alertClickToDialCalls>false</alertClickToDialCalls>
        <alertGroupPagingCalls>false</alertGroupPagingCalls>
        <enableDiversionInhibitor>false</enableDiversionInhibitor>
        <requireAnswerConfirmation>false</requireAnswerConfirmation>
        <broadworksCallControl>false</broadworksCallControl>
        <useSettingLevel>Group</useSettingLevel>
        <denyCallOriginations>false</denyCallOriginations>
        <denyCallTerminations>false</denyCallTerminations>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserBroadWorksMobilityModifyRequest", req)
        response = self.__send_request(request)
        return response

    def EnterpriseBroadWorksMobilityMobileSubscriberDirectoryNumberGetAvailableListRequest(self, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get available numbera")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>"""

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body(
            "EnterpriseBroadWorksMobilityMobileSubscriberDirectoryNumberGetAvailableListRequest", req)
        response = self.__send_request(request)
        return response

    def EnterpriseBroadWorksMobilityMobileSubscriberDirectoryNumberGetAssignmentListRequest(self, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get assigned Mobility numbers")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <responseSizeLimit>1000</responseSizeLimit>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body(
            "EnterpriseBroadWorksMobilityMobileSubscriberDirectoryNumberGetAssignmentListRequest", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderScheduleAddRequest(self, ent_id, name, shedule_type='Time'):
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <scheduleName>""" + name + """</scheduleName>
        """
        if shedule_type == 'Time':
            logging.info(
                self.LOGNAME + "Send request to BWKS to add Time Shedule: '" + name + "' to the enterprise: '" + ent_id + "'")
            reqst += """<scheduleType>Time</scheduleType>
        """
        else:
            logging.info(
                self.LOGNAME + "Send request to BWKS to add Holiday Shedule: '" + name + "' to the enterprise: '" + ent_id + "'")
            reqst += """<scheduleType>Holiday</scheduleType>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderScheduleAddRequest", req)
        response = self.__send_request(request)
        return response

    
    def ServiceProviderScheduleDeleteListRequest(self, ent_id, name, shedule_type='Time'):
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <scheduleKey>
          <scheduleName>""" + name + """</scheduleName>
          """
        if shedule_type == 'Time':
            logging.info(
                self.LOGNAME + "Send request to BWKS to delete Time Shedule: '" + name + "' from the enterprise: '" + ent_id + "'")
            reqst += """<scheduleType>Time</scheduleType>
        """
        else:
            logging.info(
                self.LOGNAME + "Send request to BWKS to delete Holiday Shedule: '" + name + "' from the enterprise: '" + ent_id + "'")
            reqst += """<scheduleType>Holiday</scheduleType>
        """
        reqst += """</scheduleKey>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderScheduleDeleteListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupCallCenterDeleteInstanceRequest(self, cc_data):
        logging.info(
            self.LOGNAME + "Send request to BWKS to delete Call Center instance from Group: " + cc_data['cc_id'])
        reqst = """
        <serviceUserId>""" + cc_data['cc_id'] + """</serviceUserId>
    """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallCenterDeleteInstanceRequest", req)
        response = self.__send_request(request)
        # if cc_data['phone'] != "" or cc_data['phone'] is not None: [incorrect conditional, it doesn't work for None]
        if cc_data['phone'] is not None:
            self.GroupDnUnassignListRequest(cc_data['ent_id'], cc_data['grp_id'], cc_data['phone'])
            self.ServiceProviderDnDeleteListRequest(cc_data['ent_id'], cc_data['phone'])
        return response

    def GroupCallCenterModifyDNISAnnouncementRequest(self, cc_id, dnis_name, data):
        logging.info(self.LOGNAME + "Send request to BWKS to delete Call Center instance from Group: " + cc_id)
        reqst = """
        <dnisKey>
          <serviceUserId>""" + cc_id + """</serviceUserId>
          <name>""" + dnis_name + """</name>
        </dnisKey>
        <mediaOnHoldSource>
          <audioMessageSourceSelection>""" + data['audioMessageSourceSelection'] + """</audioMessageSourceSelection>
          """
        if not data["externalAudioSource"]:
            reqst += """<externalAudioSource xsi:nil="true"/>
        </mediaOnHoldSource>
    """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallCenterModifyDNISAnnouncementRequest", req)
        response = self.__send_request(request)
        return response
    
    def GroupCallCenterModifyDNISRequest(self, cc, dnis_name, dict_1={}):
        dict_2 = {}
        dict_2['useCustomCLIDSettings'] = 'false'
        dict_2['useCustomDnisAnnouncementSettings'] = 'false'
        dict_2['priority'] = '2 - Medium'
        dict_2['allowOutgoingACDCall'] = 'false'
        # Let`s merge two dictionaries to the third which will be used in request
        if dict_1:
            dict_3 = dict_2.copy()
            dict_3.update(dict_1)
        else:  # Use default values
            dict_3 = dict_2
        logging.info(self.LOGNAME + "Send request to BWKS to modify DNIS '%s' of '%s' Call Center" % (dnis_name,cc.entity_id))
        reqst = """
        <dnisKey>
          <serviceUserId>""" + cc.entity_id + """</serviceUserId>
          <name>""" + dnis_name + """</name>
        </dnisKey>
        <useCustomCLIDSettings>""" + dict_3['useCustomCLIDSettings'] + """</useCustomCLIDSettings>
        <callingLineIdPhoneNumber>""" + cc.entity_phone + """</callingLineIdPhoneNumber>
        <callingLineIdLastName>""" + cc.entity_phone + """</callingLineIdLastName>
        <callingLineIdFirstName>""" + cc.entity_phone + """</callingLineIdFirstName>
        <useCustomDnisAnnouncementSettings>""" + dict_3['useCustomDnisAnnouncementSettings'] + """</useCustomDnisAnnouncementSettings>
        <priority>""" + dict_3['priority'] + """</priority>
        <allowOutgoingACDCall>""" + dict_3['allowOutgoingACDCall'] + """</allowOutgoingACDCall>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallCenterModifyDNISRequest", req)
        response = self.__send_request(request)
        return response
    
    def UserCallCenterGetRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to Get info of Call Centers for user: '%s'" % user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserCallCenterGetRequest19", req)
        response = self.__send_request(request)
        return response 

    def GroupCallCenterGetDNISRequest(self, cc_id, dnis_name):
        logging.info(
            self.LOGNAME + "Send request to BWKS to get info about DNIS: '" + dnis_name + "' of Call Center: '" + cc_id + "'")
        reqst = """
        <dnisKey>
          <serviceUserId>""" + cc_id + """</serviceUserId>
          <name>""" + dnis_name + """</name>
        </dnisKey>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallCenterGetDNISRequest", req)
        response = self.__send_request(request)
        return response

    def GroupCallCenterGetDNISListRequest(self, cc_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get list of DNIS of Call Center: '" + cc_id + "'")
        reqst = """
        <serviceUserId>""" + cc_id + """</serviceUserId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallCenterGetDNISListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupCallCenterDeleteDNISRequest(self, cc_id, dnis_name):
        logging.info(
            self.LOGNAME + "Send request to BWKS to delete DNIS: '" + dnis_name + "' in Call Center: '" + cc_id + "'")
        reqst = """
        <dnisKey>
          <serviceUserId>""" + cc_id + """</serviceUserId>
          <name>""" + dnis_name + """</name>
        </dnisKey>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallCenterDeleteDNISRequest", req)
        response = self.__send_request(request)
        return response

    def GroupCallCenterAddDNISRequest(self, cc_id, dict_1={}):
        dict_2 = {}
        dict_2['useCustomCLIDSettings'] = 'false'
        dict_2['useCustomDnisAnnouncementSettings'] = 'false'
        dict_2['priority'] = '0 - Highest'
        dict_2['allowOutgoingACDCall'] = 'false'

        # Let`s merge two dictionaries to the third which will be used in request
        if dict_1:
            dict_3 = dict_2.copy()
            dict_3.update(dict_1)
        else:  # Use default values
            dict_3 = dict_2

        logging.info(
            self.LOGNAME + "Send request to BWKS to add DNIS: '" + dict_3['name'] + "' to Call Center: '" + cc_id + "'")
        reqst = """
        <dnisKey>
          <serviceUserId>""" + cc_id + """</serviceUserId>
          <name>""" + dict_3['name'] + """</name>
        </dnisKey>
        <dnisPhoneNumber>""" + dict_3['dnisPhoneNumber'] + """</dnisPhoneNumber>
        <extension>""" + dict_3['dnisPhoneNumber'][-4:] + """</extension>
        <useCustomCLIDSettings>""" + dict_3['useCustomCLIDSettings'] + """</useCustomCLIDSettings>
        <useCustomDnisAnnouncementSettings>""" + dict_3['useCustomDnisAnnouncementSettings'] + """</useCustomDnisAnnouncementSettings>
        <priority>""" + dict_3['priority'] + """</priority>
        <allowOutgoingACDCall>""" + dict_3['allowOutgoingACDCall'] + """</allowOutgoingACDCall>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallCenterAddDNISRequest", req)
        response = self.__send_request(request)
        return response

    def GroupScheduleAddRequest(self, ent_id, gr_id, name, schedule_type="Time"):
        logging.info(self.LOGNAME + "Send request to BWKS to add Group Time/Holiday schedule: " + name)
        reqst = """<serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + gr_id + """</groupId>
        <scheduleName>""" + name + """</scheduleName>
        """
        if schedule_type == "Time":
            reqst += """<scheduleType>Time</scheduleType>
    """
        elif schedule_type == "Holiday":
            reqst += """<scheduleType>Holiday</scheduleType>
    """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupScheduleAddRequest", req)
        response = self.__send_request(request)
        return response

    def GroupScheduleGetListRequest(self,ent_id,gr_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get group schedule: " )
        reqst="""<serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + gr_id + """</groupId>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupScheduleGetListRequest17sp1", req)
        response = self.__send_request(request)
        return response
    
    def GroupScheduleGetEventRequest(self,ent_id,gr_id,sch_name,sch_type,event_name=1):
        logging.info(self.LOGNAME + "Send request to BWKS to get group schedule event: " )
        reqst="""<serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + gr_id + """</groupId>
        <scheduleKey><scheduleName>"""+sch_name+"""</scheduleName><scheduleType>"""+sch_type+"""</scheduleType></scheduleKey>
        <eventName>"""+str(event_name)+"""</eventName>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupScheduleGetEventRequest", req)
        response = self.__send_request(request)
        return response

    def GroupScheduleDeleteListRequest(self, ent_id, gr_id, name, schedule_type="Time"):
        logging.info(self.LOGNAME + "Send request to BWKS to add Group Time/Holiday schedule: " + name)
        reqst = """<serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + gr_id + """</groupId>
        <scheduleKey>
          <scheduleName>""" + name + """</scheduleName>
          """
        if schedule_type == 'Time':
            reqst += """<scheduleType>Time</scheduleType>
        </scheduleKey>
      """
        elif schedule_type == "Holiday":
            reqst += """<scheduleType>Holiday</scheduleType>
        </scheduleKey>
      """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupScheduleDeleteListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupDnAssignListRequest(self, ent_id, group_id, tn_min, tn_max, ccode=None, phone_number=None):
        if ccode is None:
            ccode = self._country_code
        logging.info(self.LOGNAME + "Send request to BWKS to add phone number to the group " + tn_min + " to " + tn_max)
        if phone_number:
            reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <phoneNumber>"""+ phone_number+"""</phoneNumber>
        """
        else:
            reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <dnRange>
            <minPhoneNumber>""" + ccode + tn_min + """</minPhoneNumber>
            <maxPhoneNumber>""" + ccode + tn_max + """</maxPhoneNumber>
        </dnRange>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupDnAssignListRequest", req)
        response = self.__send_request(request)

        return response

    def GroupAssignedServicesGetListRequest(self, ent_id, group_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get assigned services of the group " + group_id )
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAssignedServicesGetListRequest", req)
        response = self.__send_request(request)

        return response

    def GroupDnUnassignListRequest(self, ent_id, group_id, tn_range, ccode=None):
        if ccode is None:
            ccode = self._country_code
        logging.info(self.LOGNAME + "Send request to BWKS to delete phone number from the group " + tn_range)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <dnRange>
            <minPhoneNumber>""" + ccode + tn_range + """</minPhoneNumber>
            <maxPhoneNumber>""" + ccode + tn_range + """</maxPhoneNumber>
        </dnRange>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupDnUnassignListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupDnGetActivationListRequest(self, ent_id, group_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get numbers activated")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupDnGetActivationListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupServiceGetAuthorizationListRequest(self, ent_id, group_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get authorized services")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupServiceGetAuthorizationListRequest", req)
        response = self.__send_request(request)
        return response

    # request for activatin'/deactivatin' phone number in group
    def GroupDnActivateListRequest(self, ent_id, group_id, phone_nr, activate=True):
        if activate:
            logging.info(self.LOGNAME + "Send request to BWKS to activate number list")
            reqst = """
            <serviceProviderId>""" + ent_id + """</serviceProviderId>
            <groupId>""" + group_id + """</groupId>
            <phoneNumber>""" + self._country_code + phone_nr + """</phoneNumber>
            """
            req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
            request = self._generate_request_body("GroupDnActivateListRequest", req)
            response = self.__send_request(request)
            return response
        else:
            logging.info(self.LOGNAME + "Send request to BWKS to deactivate number list")
            reqst = """
            <serviceProviderId>""" + ent_id + """</serviceProviderId>
            <groupId>""" + group_id + """</groupId>
            <phoneNumber>""" + phone_nr + """</phoneNumber>
            """
            req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
            request = self._generate_request_body("GroupDnDeactivateListRequest", req)
            response = self.__send_request(request)
            return response

    def GroupAccessDeviceAddRequest14(self, ent_id, group_id=None, device_data=None):
        group_section = ''
        if group_id is not None:
            group_section = '<groupId>' + group_id + '</groupId>'

        logging.info(self.LOGNAME + "Send request to BWKS to add Device to the Group")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """ + group_section + """
        <deviceName>""" + device_data['device_name'] + """</deviceName>
        <deviceType>""" + device_data['device_type'] + """</deviceType>
        """
        if 'device_mac' in device_data:
            reqst += """<macAddress>""" + device_data['device_mac'] + """</macAddress>"""
        if 'ip' in device_data:
            reqst += """<netAddress>""" + device_data['ip'] + """</netAddress>"""
        if 'physical_location' in device_data:
            reqst += """<physicalLocation>""" + device_data['physical_location'] + """</physicalLocation>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAccessDeviceAddRequest14", req)
        response = self.__send_request(request)

        return response

    def ServiceProviderAccessDeviceAddRequest14(self, ent_id, device_data=None):
        logging.info(self.LOGNAME + "Send request to BWKS to add Device to the Group")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <deviceName>""" + device_data['device_name'] + """</deviceName>
        <deviceType>""" + device_data['device_type'] + """</deviceType>
        """
        if 'device_mac' in device_data:
            reqst += """<macAddress>""" + device_data['device_mac'] + """</macAddress>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderAccessDeviceAddRequest14", req)
        response = self.__send_request(request)

        return response

    def SystemAccessDeviceAddRequest(self, device_data):
        logging.info(self.LOGNAME + "Send request to BWKS to add Device to the System")
        reqst = """
        <deviceName>""" + device_data['deviceName'] + """</deviceName>
        <deviceType>""" + device_data['deviceType'] + """</deviceType>
        <protocol>SIP 2.0</protocol>
        """
        try:
            reqst += """<macAddress>""" + device_data['macAddress'] + """</macAddress>
        """
        except KeyError:
            pass
        try:
            reqst += """<transportProtocol>""" + device_data['transportProtocol'] + """</transportProtocol>
        """
        except KeyError:
            pass
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemAccessDeviceAddRequest", req)
        response = self.__send_request(request)
        return response

    def GroupAccessDeviceGetListRequest(self, ent_id, group_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get all devices from Group")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAccessDeviceGetListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupAccessDeviceCustomTagGetListRequest(self, ent_id, group_id, device_name):
        logging.info(
            self.LOGNAME + "Send request to BWKS to get all custom tags of device: '" + device_name + "' in group: " + ent_id + ":" + group_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <deviceName>""" + device_name + """</deviceName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAccessDeviceCustomTagGetListRequest", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderAccessDeviceCustomTagGetListRequest(self, ent_id, device_name):
        logging.info(
            self.LOGNAME + "Send request to BWKS to get all custom tags of service provider level device: '" + device_name + "' in service provider: " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <deviceName>""" + device_name + """</deviceName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderAccessDeviceCustomTagGetListRequest", req)
        response = self.__send_request(request)
        return response

    def SystemAccessDeviceCustomTagGetListRequest(self, device_name):
        logging.info(self.LOGNAME + "Send request to BWKS to get all custom tags of system device: '" + device_name)
        reqst = """
        <deviceName>""" + device_name + """</deviceName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemAccessDeviceCustomTagGetListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupAccessDeviceCustomTagAddRequest(self, ent_id, group_id, device_data):
        logging.info(self.LOGNAME + "Send request to BWKS to add Device tag to the Device")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <deviceName>""" + device_data['deviceName'] + """</deviceName>
        <tagName>""" + device_data['tagName'] + """</tagName>
        """
        if device_data['tagValue']:
            reqst += """<tagValue>""" + device_data['tagValue'] + """</tagValue>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAccessDeviceCustomTagAddRequest", req)
        response = self.__send_request(request)
        return response

    def GroupAccessDeviceCustomTagModifyRequest(self, ent_id, group_id, device_data):
        logging.info(
            self.LOGNAME + "Send request to BWKS to modify '" + device_data['tagName'] + "' custom tag for device: '" +
            device_data['deviceName'] + "' on following value: '" + device_data['tagValue'] + "'")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <deviceName>""" + device_data['deviceName'] + """</deviceName>
        <tagName>""" + device_data['tagName'] + """</tagName>
        <tagValue>""" + device_data['tagValue'] + """</tagValue>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAccessDeviceCustomTagModifyRequest", req)
        response = self.__send_request(request)
        return response

    def GroupAccessDeviceCustomTagDeleteListRequest(self, ent_id, group_id, device_data):
        logging.info(self.LOGNAME + "Send request to BWKS to add Device tag to the Group")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <deviceName>""" + device_data['deviceName'] + """</deviceName>
        <tagName>""" + device_data['tagName'] + """</tagName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAccessDeviceCustomTagDeleteListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupCPEConfigRebuildDeviceConfigFileRequest(self, ent_id, group_id, device_data):
        logging.info(self.LOGNAME + "Send request to BWKS to rebuild config Device file to the Group")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <deviceName>""" + device_data['device_name'] + """</deviceName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCPEConfigRebuildDeviceConfigFileRequest", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderDnDeleteListRequest(self, ent_id, tn_range, ccode=None):
        if ccode is None:
            ccode = self._country_code
        logging.info(self.LOGNAME + "Send request to BWKS to delete phone number from the enterprise " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <dnRange>
            <minPhoneNumber>""" + ccode + tn_range + """</minPhoneNumber>
            <maxPhoneNumber>""" + ccode + tn_range + """</maxPhoneNumber>
        </dnRange>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderDnDeleteListRequest", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderDnGetSummaryListRequest(self, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve left phone numbers from the enterprise " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderDnGetSummaryListRequest", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderDnGetAvailableListRequest(self, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve left phone numbers from the enterprise " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderDnGetAvailableListRequest", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderAnswerConfirmationGetRequest16(self, ent_id):
        logging.info(
            self.LOGNAME + "Send request to BWKS to retrieve answer confirmation settings from the enterprise " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderAnswerConfirmationGetRequest16", req)
        response = self.__send_request(request)
        return response

    def EnterpriseVoiceVPNGetRequest14sp3(self, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve voice VPN settings from the enterprise " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("EnterpriseVoiceVPNGetRequest14sp3", req)
        response = self.__send_request(request)
        return response

    def EnterpriseCallCenterEnhancedReportingModifyRequest(self,ent_id):
        logging.info(" send request to Bwks to modify the call center external reporting settings")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId><reportingServer>Enhanced</reportingServer>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("EnterpriseCallCenterEnhancedReportingModifyRequest19", req)
        response = self.__send_request(request)
        return response
    
    def GroupDnGetAvailableListRequest(self, ent_id, grp_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve left phone numbers from the group " + grp_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupDnGetAvailableListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupVoiceMessagingGroupGetVoicePortalRequest17sp4(self, ent_id, grp_id):
        logging.info(
            self.LOGNAME + "Send request to BWKS to retrieve Group Voice Portal settings from the group " + grp_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupVoiceMessagingGroupGetVoicePortalRequest17sp4", req)
        response = self.__send_request(request)
        return response

    def UserScheduleGetListRequest(self,user_id):
        logging.info("Send request to BWKS to get the schedules available for user")
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserScheduleGetListRequest17sp1", req)
        response = self.__send_request(request)
        return response
    
    def UserScheduleGetEventRequest(self,user_id,sch_name,sch_type,event_name=1):
        logging.info("Send request to BWKS to get the events in the schedule for user")
        reqst = """
        <userId>""" + user_id + """</userId>
        <scheduleKey><scheduleName>"""+sch_name+"""</scheduleName><scheduleType>"""+sch_type+"""</scheduleType></scheduleKey>
        <eventName>"""+str(event_name)+"""</eventName>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserScheduleGetEventRequest", req)
        response = self.__send_request(request)
        return response
    
    def UserVoiceMessagingUserGetVoicePortalRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve Voice Portal settings of user: '%s'" % user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserVoiceMessagingUserGetVoicePortalRequest16", req)
        response = self.__send_request(request)
        return response

    def UserVoiceMessagingUserGetVoiceManagementRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve Voice Management settings of user: '%s'" % user_id)
        reqst = """
            <userId>""" + user_id + """</userId>
            """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserVoiceMessagingUserGetVoiceManagementRequest17", req)
        response = self.__send_request(request)
        return response

    def UserVoicePortalCallingGetRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve Voice Portal Calling settings of user: '%s'" % user_id)
        reqst = """
            <userId>""" + user_id + """</userId>
            """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserVoicePortalCallingGetRequest", req)
        response = self.__send_request(request)
        return response

    def GroupVoiceMessagingGroupModifyVoicePortalRequest(self, ent_id, grp_id, vp_data):
        logging.info(
            self.LOGNAME + "Send request to BWKS to retrieve Group Voice Portal settings from the group " + grp_id)
        if vp_data['phoneNumber'] is None:
            tnElement = """<phoneNumber xsi:nil="true"/>"""
        else:
            tnElement = """<phoneNumber>""" + vp_data['phoneNumber'] + """</phoneNumber>"""
        if vp_data['extension'] is None:
            extElement = """<extension xsi:nil="true"/>"""
        else:
            extElement = """<extension>""" + vp_data['extension'] + """</extension>"""
        if "ncos" in vp_data:
            ncosElemet = """<networkClassOfService>""" + vp_data["ncos"] + """</networkClassOfService>"""
        else:
            ncosElemet = """<networkClassOfService>MIA NCOS</networkClassOfService>"""
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        <serviceInstanceProfile>
            <name>""" + vp_data['name'] + """</name>
            <callingLineIdLastName>""" + vp_data['name'] + """</callingLineIdLastName>
            <callingLineIdFirstName>""" + vp_data['name'] + """</callingLineIdFirstName>
            """ + tnElement + """
            """ + extElement + """
            <language>English</language>
            <timeZone>America/New_York</timeZone>
            <sipAliasList xsi:nil="true"/>
            <publicUserIdentity xsi:nil="true"/>
        </serviceInstanceProfile>
        <isActive>""" + vp_data['isActive'] + """</isActive>
        <enableExtendedScope>false</enableExtendedScope>
        <allowIdentificationByPhoneNumberOrVoiceMailAliasesOnLogin>false</allowIdentificationByPhoneNumberOrVoiceMailAliasesOnLogin>
        <useVoicePortalWizard>true</useVoicePortalWizard>
        <voicePortalExternalRoutingScope>System</voicePortalExternalRoutingScope>
        <useExternalRouting>false</useExternalRouting>
        <externalRoutingAddress xsi:nil="true"/>
        <homeZoneName xsi:nil="true"/>
        """ + ncosElemet + """
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupVoiceMessagingGroupModifyVoicePortalRequest", req)
        response = self.__send_request(request)
        return response

    def GroupDnGetAssignmentListRequest(self, ent_id, grp_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve left phone numbers from the group " + grp_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupDnGetAssignmentListRequest", req)
        response = self.__send_request(request)
        return response

    # NOTE THAT service_names and  sp_names should be a list
    def UserServiceAssignListRequest(self, user_id, host='', service_names=[], sp_names=[]):
        logging.info(self.LOGNAME + "Send request to BWKS to  assign Service or Service Pack to " + user_id + host)
        reqst = """
        <userId>""" + user_id + host + """</userId>
        """
        if service_names:
            for i in service_names:
                reqst += """<serviceName>""" + i + """</serviceName>
        """
        if sp_names:
            for j in sp_names:
                reqst += """<servicePackName>""" + j + """</servicePackName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserServiceAssignListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupServiceInstancePrivacyModifyRequest(self, service_id):
        logging.info(self.LOGNAME + "Send request to BWKS to  Modify Privacy for user: " + service_id)
        reqst = """
        <serviceUserId>""" + service_id + """</serviceUserId>
        <enableDirectoryPrivacy>true</enableDirectoryPrivacy>
        <enableAutoAttendantExtensionDialingPrivacy>false</enableAutoAttendantExtensionDialingPrivacy>
        <enableAutoAttendantNameDialingPrivacy>false</enableAutoAttendantNameDialingPrivacy>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupServiceInstancePrivacyModifyRequest", req)
        response = self.__send_request(request)
        return response

    def GroupAutoAttendantSubmenuGetListRequest(self, serviceUserId):
        logging.info(self.LOGNAME + "Send request to BWKS to get List of Submenus in Auto-Attendant: " + serviceUserId)
        reqst = """<serviceUserId>""" + serviceUserId + """</serviceUserId>
      """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAutoAttendantSubmenuGetListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupAutoAttendantDeleteInstanceRequest(self, user_id, ent_id="", group_id="", delete_tn=False):
        logging.info(self.LOGNAME + "Send request to BWKS to delete Auto-Attendant: '" + user_id + "'")
        reqst = """
        <serviceUserId>""" + user_id + """</serviceUserId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupAutoAttendantDeleteInstanceRequest", req)
        response = self.__send_request(request)
        if delete_tn:
            self.GroupDnUnassignListRequest(ent_id, group_id, user_id)
            self.ServiceProviderDnDeleteListRequest(ent_id, user_id)
        return response

    def EnterpriseSessionAdmissionControlGroupAddRequest(self, pattern):
        req = pattern.get_all_sections()
        req = req.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("EnterpriseSessionAdmissionControlGroupAddRequest", req)
        response = self.__send_request(request)

        return response
    def GroupScheduleAddRequest(self, ent_id, gr_id, name, schedule_type="Time"):
        logging.info(self.LOGNAME + "Send request to BWKS to add Group Time/Holiday schedule: " + name)
        reqst = """<serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + gr_id + """</groupId>
        <scheduleName>""" + name + """</scheduleName>
        <scheduleType>""" + schedule_type + """</scheduleType>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupScheduleAddRequest", req)
        response = self.__send_request(request)
        return response

    def GroupScheduleDeleteListRequest(self, ent_id, gr_id, name, schedule_type="Time"):
        logging.info(self.LOGNAME + "Send request to BWKS to add Group Time/Holiday schedule: " + name)
        reqst = """<serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + gr_id + """</groupId>
        <scheduleKey>
          <scheduleName>""" + name + """</scheduleName>
          """
        if schedule_type == 'Time':
            reqst += """<scheduleType>Time</scheduleType>
        </scheduleKey>
      """
        elif schedule_type == "Holiday":
            reqst += """<scheduleType>Holiday</scheduleType>
        </scheduleKey>
      """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupScheduleDeleteListRequest", req)
        response = self.__send_request(request)
        return response

    def EnterpriseSessionAdmissionControlGroupDeleteListRequest(self, ent_id, sac_name):
        req = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <name>""" + sac_name + """</name>
        """
        req = req.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("EnterpriseSessionAdmissionControlGroupDeleteListRequest", req)
        response = self.__send_request(request)

        return response

    def GroupSessionAdmissionControlGroupGetListRequest(self, pattern):
        req = pattern.get_all_sections()
        req = req.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupSessionAdmissionControlGroupGetListRequest", req)
        response = self.__send_request(request)

        return response

    def GroupSessionAdmissionControlGroupDeleteListRequest(self, pattern):
        req = pattern.get_all_sections()
        req = req.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupSessionAdmissionControlGroupDeleteListRequest", req)
        response = self.__send_request(request)

        return response

    def GroupInterceptGroupGetRequest16sp1(self, pattern):
        req = pattern.get_all_sections()
        req = req.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupInterceptGroupGetRequest16sp1", req)
        response = self.__send_request(request)

        return response

    def UserServiceUnassignListRequest(self, user_id, host='', service_names=[], sp_names=[]):
        logging.info(self.LOGNAME + "Send request to BWKS to  unassign Service or Service Pack from " + user_id + host)
        reqst = """
        <userId>""" + user_id + host + """</userId>
        """
        if service_names:
            for i in service_names:
                reqst += """<serviceName>""" + i + """</serviceName>
        """
        if sp_names:
            for j in sp_names:
                reqst += """<servicePackName>""" + j + """</servicePackName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserServiceUnassignListRequest", req)
        response = self.__send_request(request)
        return response

    def UserBroadWorksMobilityMobileIdentityAddRequest(self, user_id, mobileNumber, isPrimary=False):
        logging.info(self.LOGNAME + "Send request to BWKS to  assign mobile TN to " + user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """

        reqst += """
        <mobileNumber>""" + mobileNumber + """</mobileNumber>
        <isPrimary>""" + str(isPrimary).lower() + """</isPrimary>
        <enableAlerting>true</enableAlerting>
 <alertAgentCalls>true</alertAgentCalls>
 <alertClickToDialCalls>false</alertClickToDialCalls>
 <alertGroupPagingCalls>false</alertGroupPagingCalls>
 <useMobilityCallingLineID>false</useMobilityCallingLineID>
 <enableDiversionInhibitor>false</enableDiversionInhibitor>
 <requireAnswerConfirmation>false</requireAnswerConfirmation>
 <broadworksCallControl>false</broadworksCallControl>
 <useSettingLevel>Group</useSettingLevel>
 <denyCallOriginations>false</denyCallOriginations>
 <denyCallTerminations>false</denyCallTerminations>
 <devicesToRing>Mobile</devicesToRing>
 <includeSharedCallAppearance>false</includeSharedCallAppearance>
 <includeBroadworksAnywhere>false</includeBroadworksAnywhere>
 <includeExecutiveAssistant>false</includeExecutiveAssistant>
 <mobileNumberAlerted>""" + mobileNumber + """</mobileNumberAlerted>
 <enableCallAnchoring>true</enableCallAnchoring>

        """

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserBroadWorksMobilityMobileIdentityAddRequest", req)
        response = self.__send_request(request)
        return response
    def GroupBroadWorksAnywhereAddInstanceRequest(self, ent_id, group_id, aa_data):
        logging.info(self.LOGNAME + "Send request to BWKS to add Broadworks Anywhere: " + aa_data['ba_name'])
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <serviceUserId>""" + aa_data['ba_id'] + """</serviceUserId>
            <serviceInstanceProfile>
                <name>""" + aa_data['ba_name'] + """</name>
                <callingLineIdLastName>""" + aa_data['ba_lname'] + """</callingLineIdLastName>
                <callingLineIdFirstName>""" + aa_data['ba_fname'] + """</callingLineIdFirstName>
                <phoneNumber>""" + self._country_code + aa_data['ba_phone'] + """</phoneNumber>
                <extension>""" + aa_data['ba_ext'] + """</extension>
                <language>English</language>
                <timeZone>America/New_York</timeZone>
            </serviceInstanceProfile>
        <broadWorksAnywhereScope>Group</broadWorksAnywhereScope>
        <promptForCLID>Prompt When Not Available</promptForCLID>
        <silentPromptMode>false</silentPromptMode>
        <promptForPasscode>false</promptForPasscode>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupBroadWorksAnywhereAddInstanceRequest", req)
        response = self.__send_request(request)
        return response
    
    

    def GroupServiceAssignListRequest(self, ent_id, group_id, group_service_names=[]):
        logging.info(self.LOGNAME + "Send request to BWKS to  Assign Group Services to Group " + group_id)
        reqst = """<serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        """
        for group_service_name in group_service_names:
            reqst += """<serviceName>""" + group_service_name + """</serviceName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupServiceAssignListRequest", req)
        # print request
        response = self.__send_request(request)

        return response

    def GroupServiceUnassignListRequest(self, ent_id, group_id, group_service_names=[]):
        logging.info(self.LOGNAME + "Send request to BWKS to  Unassign Group Services from Group " + group_id)
        reqst = """<serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        """
        for group_service_name in group_service_names:
            reqst += """<serviceName>""" + group_service_name + """</serviceName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupServiceUnassignListRequest", req)
        response = self.__send_request(request)
        return response

    def GroupServiceModifyAuthorizationListRequest(self, ent_id, group_id, sp_names=[], group_service_names=[],
                                                   user_service_names=[], authorize=True, limit=None):
        limit_str = ''
        if limit is None:
            limit_str = '<unlimited>true</unlimited>'
        else:
            limit_str = '<quantity>' + limit + '</quantity>'
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        """
        if authorize:
            logging.info(
                self.LOGNAME + "Send request to BWKS to  authorize services/service packs on group " + group_id)
            if sp_names:
                for sp_name in sp_names:
                    reqst += """<servicePackAuthorization>
          <servicePackName>""" + sp_name + """</servicePackName>
          <authorizedQuantity>""" + limit_str + """
          </authorizedQuantity>
        </servicePackAuthorization>
        """
            if group_service_names:
                for group_service_name in group_service_names:
                    reqst += """<groupServiceAuthorization>
          <serviceName>""" + group_service_name + """</serviceName>
          <authorizedQuantity>""" + limit_str + """
          </authorizedQuantity>
        </groupServiceAuthorization>
        """
            if user_service_names:
                for user_service_name in user_service_names:
                    reqst += """<userServiceAuthorization>
          <serviceName>""" + user_service_name + """</serviceName>
          <authorizedQuantity>""" + limit_str + """
          </authorizedQuantity>
        </userServiceAuthorization>
        """
        # ELSE IF NEED TO UNAUTHORIZE
        else:
            logging.info(
                self.LOGNAME + "Send request to BWKS to  unauthorize services/service packs from group " + group_id)
            if sp_names:
                for sp_name in sp_names:
                    reqst += """<servicePackAuthorization>
          <servicePackName>""" + sp_name + """</servicePackName>
          <unauthorized>true</unauthorized>
        </servicePackAuthorization>
        """
            if group_service_names:
                for group_service_name in group_service_names:
                    reqst += """<groupServiceAuthorization>
          <serviceName>""" + group_service_name + """</serviceName>
          <unauthorized>true</unauthorized>
        </groupServiceAuthorization>
        """
            if user_service_names:
                for user_service_name in user_service_names:
                    reqst += """<userServiceAuthorization>
          <serviceName>""" + user_service_name + """</serviceName>
          <unauthorized>true</unauthorized>
        </userServiceAuthorization>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupServiceModifyAuthorizationListRequest", req)
        response = self.__send_request(request)

        return response

    def anotherServiceProviderServiceModifyAuthorizationListRequest(self, ent_id, sp_names=[], group_service_names=[],
                                                                    user_service_names=[], authorize=True):
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        if authorize:
            logging.info(
                self.LOGNAME + "Send request to BWKS to  authorize services/service packs on enterprise " + ent_id)
            if sp_names:
                for sp_name in sp_names:
                    reqst += """<servicePackAuthorization>
          <servicePackName>""" + sp_name + """</servicePackName>
          <authorizedQuantity>
            <unlimited>true</unlimited>
          </authorizedQuantity>
        </servicePackAuthorization>
        """
            if group_service_names:
                for group_service_name in group_service_names:
                    reqst += """<groupServiceAuthorization>
          <serviceName>""" + group_service_name + """</serviceName>
          <authorizedQuantity>
            <unlimited>true</unlimited>
          </authorizedQuantity>
        </groupServiceAuthorization>
        """
            if user_service_names:
                for user_service_name in user_service_names:
                    reqst += """<userServiceAuthorization>
          <serviceName>""" + user_service_name + """</serviceName>
          <authorizedQuantity>
            <unlimited>true</unlimited>
          </authorizedQuantity>
        </userServiceAuthorization>
        """
        # ELSE IF NOT AUTHORIZE
        else:
            logging.info(
                self.LOGNAME + "Send request to BWKS to  unauthorize services/service packs from ent " + ent_id)
            if sp_names:
                for sp_name in sp_names:
                    reqst += """<servicePackAuthorization>
          <servicePackName>""" + sp_name + """</servicePackName>
          <unauthorized>true</unauthorized>
        </servicePackAuthorization>
        """
            if group_service_names:
                for group_service_name in group_service_names:
                    reqst += """<groupServiceAuthorization>
          <serviceName>""" + group_service_name + """</serviceName>
          <unauthorized>true</unauthorized>
        </groupServiceAuthorization>
        """
            if user_service_names:
                for user_service_name in user_service_names:
                    reqst += """<userServiceAuthorization>
          <serviceName>""" + user_service_name + """</serviceName>
          <unauthorized>true</unauthorized>
        </userServiceAuthorization>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderServiceModifyAuthorizationListRequest", req)
        response = self.__send_request(request)
        return response

    # method for modifying service authorization limits. Quantity=0 stands for unlimited:
    def ModifyServicesLimitsForGroup(self, ent_id, group_id, service_name, quantity, user_service=True):
        logging.info(
            self.LOGNAME + "Send request to BWKS to change authorization limits for service " + service_name + " on group " + group_id)
        if user_service:
            tag_name = 'userServiceAuthorization'
        else:
            tag_name = 'groupServiceAuthorization'

        if quantity <= 0:
            quantity_str = '<unlimited>true</unlimited>'
        else:
            quantity_str = '<quantity>{}</quantity>'.format(quantity)

        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        """
        reqst += """<{tag_name}>
          <serviceName>{service_name}</serviceName>
          <authorizedQuantity>
            {quantity_str}
          </authorizedQuantity>
        </{tag_name}>
        """.format(tag_name=tag_name, service_name=service_name, quantity_str=quantity_str)
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupServiceModifyAuthorizationListRequest", req)
        response = self.__send_request(request)
        return response

    # method for modifying service pack authorization limits. Quantity=0 stands for unlimited:
    def ModifyServicePacksLimitsForGroup(self, ent_id, group_id, service_pack_name, quantity):
        logging.info(
            self.LOGNAME + "Send request to BWKS to change authorization limits for service pack" + service_pack_name + " on group " + group_id)

        if quantity <= 0:
            quantity_str = '<unlimited>true</unlimited>'
        else:
            quantity_str = '<quantity>{}</quantity>'.format(quantity)

        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        """
        reqst += """<servicePackAuthorization>
          <servicePackName>{service_pack_name}</servicePackName>
          <authorizedQuantity>
            {quantity_str}
          </authorizedQuantity>
        </servicePackAuthorization>
        """.format(service_pack_name=service_pack_name, quantity_str=quantity_str)
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupServiceModifyAuthorizationListRequest", req)
        response = self.__send_request(request)
        return response

    def ServiceProviderServicePackAddRequest(self, ent_id, sp_name, services_name=[], sp_desc='',
                                             isAvailableForUse='true', servicePackQuantity='unlimited'):
        logging.info(self.LOGNAME + "Send request to BWKS to add a service pack to a service provider " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <servicePackName>""" + sp_name + """</servicePackName>
        """
        if sp_desc != '':
            reqst = reqst + """<servicePackDescription>""" + sp_desc + """</servicePackDescription>
        """
        reqst = reqst + """<isAvailableForUse>""" + isAvailableForUse + """</isAvailableForUse>
        <servicePackQuantity>
            """
        if servicePackQuantity == 'unlimited':
            reqst = reqst + """<unlimited>true</unlimited>
        </servicePackQuantity>
        """
        else:
            reqst = reqst + """<quantity>""" + servicePackQuantity + """</quantity>
        </servicePackQuantity>
        """
        for service in services_name:
            reqst = reqst + """<serviceName>""" + service + """</serviceName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderServicePackAddRequest", req)
        response = self.__send_request(request)

        return response

    def SiteDeleteRequest(self, customer_id, site_id):
        logging.info(
            self.LOGNAME + "Send request to BWKS to delete Group " + site_id + " from enterprise " + customer_id)
        reqst = """
        <customerId>""" + customer_id + """</customerId>
        <siteId>""" + site_id + """</siteId>
        """

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SiteDeleteRequest", req)
        response = self.__send_request(request)

        return response

    def SystemPasswordRulesModifyRequest14Sp3(self):
        logging.info(self.LOGNAME + "Send request to BWKS to set default password rules")
        reqst = """
        <rulesApplyTo>System, Provisioning, Service Provider Administrator</rulesApplyTo>
        <allowWebAddExternalAuthenticationUsers>true</allowWebAddExternalAuthenticationUsers>
        <disallowUserId>true</disallowUserId>
        <disallowOldPassword>false</disallowOldPassword>
        <disallowReversedOldPassword>false</disallowReversedOldPassword>
        <restrictMinDigits>false</restrictMinDigits>
        <minDigits>1</minDigits>
        <restrictMinUpperCaseLetters>false</restrictMinUpperCaseLetters>
        <minUpperCaseLetters>1</minUpperCaseLetters>
        <restrictMinLowerCaseLetters>false</restrictMinLowerCaseLetters>
        <minLowerCaseLetters>1</minLowerCaseLetters>
        <restrictMinNonAlphanumericCharacters>false</restrictMinNonAlphanumericCharacters>
        <minNonAlphanumericCharacters>1</minNonAlphanumericCharacters>
        <minLength>5</minLength>
        <maxFailedLoginAttempts>5</maxFailedLoginAttempts>
        <passwordExpiresDays>0</passwordExpiresDays>
        <sendLoginDisabledNotifyEmail>false</sendLoginDisabledNotifyEmail>
        <loginDisabledNotifyEmailAddress xsi:nil="true"/>
        <disallowPreviousPasswords>false</disallowPreviousPasswords>
        <numberOfPreviousPasswords>1</numberOfPreviousPasswords>
        """

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemPasswordRulesModifyRequest14Sp3", req)
        response = self.__send_request(request)

        return response

    def ServiceProviderPasswordRulesModifyRequest14Sp3(self, sp):
        logging.info(self.LOGNAME + "Send request to BWKS to set default password rules for service provider: " + sp)
        reqst = """
        <serviceProviderId>""" + sp + """</serviceProviderId>
        <rulesApplyTo>Administrator</rulesApplyTo>
        <allowWebAddExternalAuthenticationUsers>false</allowWebAddExternalAuthenticationUsers>
        <disallowUserId>true</disallowUserId>
        <disallowOldPassword>false</disallowOldPassword>
        <disallowReversedOldPassword>false</disallowReversedOldPassword>
        <restrictMinDigits>false</restrictMinDigits>
        <minDigits>1</minDigits>
        <restrictMinUpperCaseLetters>false</restrictMinUpperCaseLetters>
        <minUpperCaseLetters>1</minUpperCaseLetters>
        <restrictMinLowerCaseLetters>false</restrictMinLowerCaseLetters>
        <minLowerCaseLetters>1</minLowerCaseLetters>
        <restrictMinNonAlphanumericCharacters>false</restrictMinNonAlphanumericCharacters>
        <minNonAlphanumericCharacters>1</minNonAlphanumericCharacters>
        <minLength>6</minLength>
        <maxFailedLoginAttempts>5</maxFailedLoginAttempts>
        <passwordExpiresDays>0</passwordExpiresDays>
        <sendLoginDisabledNotifyEmail>false</sendLoginDisabledNotifyEmail>
        <loginDisabledNotifyEmailAddress xsi:nil="true"/>
        <disallowPreviousPasswords>false</disallowPreviousPasswords>
        <numberOfPreviousPasswords>1</numberOfPreviousPasswords>
        """

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderPasswordRulesModifyRequest14Sp3", req)
        response = self.__send_request(request)

        return response

    def ServiceProviderPasswordRulesModifyRequest(self, sp, ppolicy_data):
        logging.info(self.LOGNAME + "Send request to BWKS to set default password rules for service provider: " + sp)
        reqst = """
        <serviceProviderId>""" + sp + """</serviceProviderId>
        <rulesApplyTo>Administrator</rulesApplyTo>
        <allowWebAddExternalAuthenticationUsers>false</allowWebAddExternalAuthenticationUsers>
        <disallowUserId>true</disallowUserId>
        <disallowOldPassword>false</disallowOldPassword>
        <disallowReversedOldPassword>false</disallowReversedOldPassword>
        <restrictMinDigits>""" + ppolicy_data['restrictMinDigits'] + """</restrictMinDigits>
        <minDigits>""" + ppolicy_data['minDigits'] + """</minDigits>
        <restrictMinUpperCaseLetters>""" + ppolicy_data['restrictMinUpperCaseLetters'] +"""</restrictMinUpperCaseLetters>
        <minUpperCaseLetters>""" + ppolicy_data['minUpperCaseLetters'] + """</minUpperCaseLetters>
        <restrictMinLowerCaseLetters>""" + ppolicy_data['restrictMinLowerCaseLetters'] + """</restrictMinLowerCaseLetters>
        <minLowerCaseLetters>""" + ppolicy_data['minLowerCaseLetters'] + """</minLowerCaseLetters>
        <restrictMinNonAlphanumericCharacters>""" + ppolicy_data['restrictMinNonAlphanumericCharacters'] + """</restrictMinNonAlphanumericCharacters>
        <minNonAlphanumericCharacters>""" + ppolicy_data['minNonAlphanumericCharacters'] + """</minNonAlphanumericCharacters>
        <minLength>""" + ppolicy_data['minLength'] + """</minLength>
        <maxFailedLoginAttempts>5</maxFailedLoginAttempts>
        <passwordExpiresDays>0</passwordExpiresDays>
        <sendLoginDisabledNotifyEmail>false</sendLoginDisabledNotifyEmail>
        <loginDisabledNotifyEmailAddress xsi:nil="true"/>
        <disallowPreviousPasswords>false</disallowPreviousPasswords>
        <numberOfPreviousPasswords>1</numberOfPreviousPasswords>
        """

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderPasswordRulesModifyRequest14Sp3", req)
        response = self.__send_request(request)

        return response

    def SystemNetworkClassOfServiceAddRequest(self, name):
        logging.info(self.LOGNAME + "Send request to BWKS to add System NCOS " + name)
        reqst = """
        <name>""" + name + """</name>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemNetworkClassOfServiceAddRequest", req)
        response = self.__send_request(request)

        return response

    def ServiceProviderNetworkClassOfServiceAssignListRequest21(self, ent_id, ncos_name, default=False):
        logging.info(self.LOGNAME + "Send request to BWKS to add NCOS " + ncos_name + " to ent: " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <networkClassOfService>""" + ncos_name + """</networkClassOfService>"""
        if default:
            reqst += """
        <defaultNetworkClassOfService>
            <networkClassOfServiceName>""" + ncos_name + """</networkClassOfServiceName>
        </defaultNetworkClassOfService>
        """
        else:
            reqst += """
        <defaultNetworkClassOfService>
            <useExisting>true</useExisting>
        </defaultNetworkClassOfService>
        """

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderNetworkClassOfServiceAssignListRequest21", req)
        response = self.__send_request(request)

        return response

    def ServiceProviderNetworkClassOfServiceAssignListRequest(self, ent_id, ncos_name, default=False):
        logging.info(self.LOGNAME + "Send request to BWKS to add NCOS " + ncos_name + " to ent: " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <networkClassOfService>""" + ncos_name + """</networkClassOfService>"""
        if default:
            reqst += """
        <defaultNetworkClassOfService>
            <networkClassOfServiceName>""" + ncos_name + """</networkClassOfServiceName>
        </defaultNetworkClassOfService>
        """
        else:
            reqst += """
        <defaultNetworkClassOfService>
            <useExisting>true</useExisting>
        </defaultNetworkClassOfService>
        """
        ocireqst = 'ServiceProviderNetworkClassOfServiceAssignListRequest'
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body(ocireqst, req)
        response = self.__send_request(request)

        return response

    def ServiceProviderNetworkClassOfServiceAssignListRequest20(self, ent_id, ncos_name, default=False):
        logging.info(self.LOGNAME + "Send request to BWKS to add NCOS " + ncos_name + " to ent: " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <networkClassOfService>""" + ncos_name + """</networkClassOfService>"""
        if default:
            reqst += """
        <defaultNetworkClassOfService>""" + ncos_name + """</defaultNetworkClassOfService>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body('ServiceProviderNetworkClassOfServiceAssignListRequest', req)
        response = self.__send_request(request)

        return response

    def ServiceProviderNetworkClassOfServiceUnassignListRequest21(self, ent_id, ncos_name, default=False):
        logging.info(self.LOGNAME + "Send request to BWKS to add NCOS " + ncos_name + " to ent: " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <networkClassOfService>""" + ncos_name + """</networkClassOfService>"""
        if default:
            reqst += """
        <defaultNetworkClassOfService>
            <networkClassOfServiceName>""" + ncos_name + """</networkClassOfServiceName>
        </defaultNetworkClassOfService>
        """
        else:
            reqst += """
        <defaultNetworkClassOfService>
            <useExisting>true</useExisting>
        </defaultNetworkClassOfService>
        """

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderNetworkClassOfServiceUnassignListRequest21", req)
        response = self.__send_request(request)

        return response

    def ServiceProviderNetworkClassOfServiceUnassignListRequest(self, ent_id, ncos_name):
        logging.info(self.LOGNAME + "Send request to BWKS to add NCOS " + ncos_name + " to ent: " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
    <networkClassOfService>""" + ncos_name + """</networkClassOfService>
        """

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderNetworkClassOfServiceUnassignListRequest", req)
        response = self.__send_request(request)

        return response

    def ServiceProviderServiceGetAuthorizationListRequest(self, ent_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get auth services of ent: " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>"""

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderServiceGetAuthorizationListRequest", req)
        response = self.__send_request(request)

        return response

    def GroupNetworkClassOfServiceAssignListRequest21(self, ent_id, group_id, ncos_name):
        logging.info(self.LOGNAME + "Send request to BWKS to add NCOS " + ncos_name + " to ent: " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
    <networkClassOfService>""" + ncos_name + """</networkClassOfService>
    <defaultNetworkClassOfService>
      <useExisting>true</useExisting>
    </defaultNetworkClassOfService>
        """

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupNetworkClassOfServiceAssignListRequest21", req)
        response = self.__send_request(request)

        return response

    def GroupNetworkClassOfServiceAssignListRequest(self, ent_id, group_id, ncos_name):
        logging.info(self.LOGNAME + "Send request to BWKS to add NCOS " + ncos_name + " to ent: " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
    <networkClassOfService>""" + ncos_name + """</networkClassOfService>
        """

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupNetworkClassOfServiceAssignListRequest", req)
        response = self.__send_request(request)

        return response

    def GroupNetworkClassOfServiceUnassignListRequest21(self, ent_id, group_id, ncos_name):
        logging.info(self.LOGNAME + "Send request to BWKS to add NCOS " + ncos_name + " to ent: " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
    <networkClassOfService>""" + ncos_name + """</networkClassOfService>
    <defaultNetworkClassOfService>
      <useExisting>true</useExisting>
    </defaultNetworkClassOfService>
        """

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupNetworkClassOfServiceUnassignListRequest21", req)
        response = self.__send_request(request)

        return response

    def GroupNetworkClassOfServiceUnassignListRequest(self, ent_id, group_id, ncos_name):
        logging.info(self.LOGNAME + "Send request to BWKS to add NCOS " + ncos_name + " to ent: " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
    <networkClassOfService>""" + ncos_name + """</networkClassOfService>
        """

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupNetworkClassOfServiceUnassignListRequest", req)
        response = self.__send_request(request)

        return response

    def ServiceProviderNetworkClassOfServiceModifyDefaultRequest(self, ent_id, name):
        logging.info(self.LOGNAME + "Send request to BWKS to set NCOS " + name + " as default")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <networkClassOfService>""" + name + """</networkClassOfService>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderNetworkClassOfServiceModifyDefaultRequest", req)
        response = self.__send_request(request)

        return response

    def ServiceProviderServicePackDeleteRequest(self, ent_id, sp_name):
        logging.info(
            self.LOGNAME + "Send request to BWKS to delete Service Pack " + sp_name + " from enterprise " + ent_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <servicePackName>""" + sp_name + """</servicePackName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderServicePackDeleteRequest", req)
        response = self.__send_request(request)

        return response

    def SystemAccessDeviceGetUserListRequest(self, device_name):
        logging.info(self.LOGNAME + "Send request to BWKS to Add Digit String")
        reqst = """
        <deviceName>""" + device_name + """</deviceName>
        <responseSizeLimit>1000</responseSizeLimit>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemAccessDeviceGetUserListRequest", req)
        response = self.__send_request(request)

        return response

    def GroupCallingPlanAddDigitPatternRequest(self, ent_id, group_id, digit_name, digit_string):
        logging.info(self.LOGNAME + "Send request to BWKS to Add Digit String")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <name>""" + digit_name + """</name>
        <digitPattern>""" + digit_string + """</digitPattern>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallingPlanAddDigitPatternRequest", req)
        response = self.__send_request(request)

        return response

    def UserSimultaneousRingPersonalGetRequest(self, user_id):
        logging.info(
            self.LOGNAME + "Send request to BWKS to parse info about Simultaneous Ring Personal service of user: '%s'" % user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserSimultaneousRingPersonalGetRequest17", req)
        response = self.__send_request(request)

        return response

    def UserSequentialRingGetRequest(self, user_id):
        logging.info(
            self.LOGNAME + "Send request to BWKS to parse info about Sequentia lRing service of user: '%s'" % user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserSequentialRingGetRequest14sp4", req)
        response = self.__send_request(request)

        return response

    def GroupCallingPlanDeleteDigitPatternListRequest(self, ent_id, group_id, digit_name):
        logging.info(self.LOGNAME + "Send request to BWKS to Delete Digit String")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <name>""" + digit_name + """</name>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupCallingPlanDeleteDigitPatternListRequest", req)
        response = self.__send_request(request)

        return response

    def UserPersonalAssistantModifyRequest(self,user_id,ddd,ttt):
        logging.info(self.LOGNAME + "Send request to BWKS to Modify the personal assistant expiration date")
        reqst="""     
        <userId>""" + user_id + """</userId>
        <presence>Business Trip</presence>
        <enableTransferToAttendant>false</enableTransferToAttendant>
        <attendantNumber xsi:nil="true"/>
        <enableRingSplash>false</enableRingSplash>
        <enableExpirationTime>true</enableExpirationTime>
        <expirationTime>"""+ddd+"""T"""+ttt+"""</expirationTime>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserPersonalAssistantModifyRequest", req)
        response = self.__send_request(request)

    def UserPrepaidGetRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS")
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserPrepaidGetRequest", req)
        response = self.__send_request(request)

        return response

    def ServiceProviderLanguageGetAvailableListRequest(self, ent_id):
        logging.info(self.LOGNAME + "Send ServiceProviderLanguageGetAvailableListRequest request to BWKS")
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderLanguageGetAvailableListRequest", req)
        response = self.__send_request(request)

        return response



    def UserVoiceMessagingUserGetAdvancedVoiceManagementRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS")
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserVoiceMessagingUserGetAdvancedVoiceManagementRequest", req)
        response = self.__send_request(request)

        return response

    def __store_nonce(self, resp):
        nonce = self.get_xml_param_value(resp.replace("-", ""), ".//nonce")
        self.nonce = nonce

    def __pretty_text_log(self, text):
        return "\n-----------------------------\n" + text.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;",
                                                                                                            "\"") + "\n-----------------------------"

    def __pretty_text(self, text):
        return text.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"")

    def __send_request(self, req):
        logging.info(self.LOGNAME + "REQUEST IS: " + self.__pretty_text_log(req))
        headers = {
            'SOAPAction': 'processOCIMessage'
        }
        s = requests.Session()
        s.mount('http://', HTTPAdapter(max_retries=30))
        s.mount('https://', HTTPAdapter(max_retries=30))
        try:
            if self.cookie == "":
                if not "@" in self._username:
                    username = self._username + "@" + self._domain
                else:
                    username = self._username
                rauth = s.post(self._url + self._provisioning_service, data=self.AuthenticationRequest(username),
                               verify=False, headers=headers)
                logging.info(self.LOGNAME + "Auth response is: " + self.__pretty_text_log(rauth.text))
                self.cookie = rauth.cookies
                self.__store_nonce(self.__pretty_text(rauth.text))
                passw = hashlib.md5((self.nonce + ':' + self._password).encode("utf-8")).hexdigest()
                logging.debug(self.LOGNAME + " Cookie: " + ": " + str(
                    self.cookie) + ", nonce: " + self.nonce + ", passw: " + passw)
                #self._password = 'admin'
                request_data = self.LoginRequest22(username, self._password)
                
                logging.debug(self.LOGNAME + " login request data: " + self.__pretty_text_log(request_data))
                rlogin = s.post(self._url + self._provisioning_service, data=request_data, verify=False,
                                headers=headers, cookies=self.cookie)
                logging.debug(self.LOGNAME + "Login response is: " + self.__pretty_text_log(rlogin.text))
            r = s.post(self._url + self._provisioning_service, data=req, verify=False, headers=headers,
                       cookies=self.cookie)
            logging.info(self.LOGNAME + "REQUEST RESPONSE IS: " + self.__pretty_text_log(r.text))
            return self.__pretty_text(r.text)
        except (Exception, data):
            logging.error(self.LOGNAME + "Error Details: " + str(data))

    # This function returns value of xml parameter if "is_present" == True and xml parameter is found in xml
    # Will fail if "is_present" == True and xml parameter not found in xml
    # Will fail if "is_present" != True and xml parameter found in xml
    def get_xml_param_value(self, xml, file_tag, is_present=True):
        print(xml)
        try:
            parser = etree.XMLParser(recover=True)
            xml = xml.replace("<?xml version='1.0' encoding='UTF-8'?>", "").encode("utf-8")
            tree = etree.fromstring(xml, parser=parser)
            value = tree.xpath(file_tag)[0].text
        except IndexError:
            if is_present:
                scr_msg = "Element '" + file_tag + "' is not found in response "
                logging.error(scr_msg)
                raise Exception(scr_msg)
            else:
                pass
        else:
            if is_present:
                return value
            else:
                scr_msg = "Element '" + file_tag + "' is found in response"
                logging.error(scr_msg)
                raise Exception(scr_msg)

    def get_xml_section_content(self, xml, section):
        logging.info(self.LOGNAME + "Let's get all content from section: " + section)
        try:
            parser = etree.XMLParser(recover=True)
            xml = xml.encode('utf-8').replace("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>", "")
            tree = etree.fromstring(xml, parser=parser)
            section_element = tree.xpath(section)
            data = etree.tostring(section_element[0])
            logging.info(self.LOGNAME + "Content is: " + str(data))
            return data
        except IndexError:
            scr_msg = "Section '" + section + "' is not found in response"
            logging.error(scr_msg)
            raise Exception(scr_msg)

    def convert_xml_to_dict(self, t):
        import xmltodict
        logging.info(self.LOGNAME + "Convert XML to dict")
        return xmltodict.parse(t)

    def verify_response_value(self, xml, tags_to_verify={}):
        for file_tag, expected_value in tags_to_verify.items():
            logging.info(self.LOGNAME + "Let's verify that value in '" + file_tag + "' of response equal to " + str(expected_value))
            actual_value = self.get_xml_param_value(xml, ".//" + file_tag)
            if actual_value != expected_value:
                scr_msg = "Actual value '" + actual_value + "' is not equal to expected: " + str(expected_value)
                logging.error(scr_msg)
                raise Exception(scr_msg)
        
    def verify_response_value_new(self, xml, file_tag, expected_value):
        logging.info(
            self.LOGNAME + "Let's verify that value in '" + file_tag + "' of response equal to " + str(expected_value))
        actual_value = self.get_xml_param_value(xml, file_tag)
        if not actual_value.find(expected_value):
            scr_msg = "Actual value '" + actual_value + "' does not have : " + expected_value
            logging.error(scr_msg)
            raise Exception(scr_msg)

    def get_all_authorized_group_services(self, xml):
        services = []
        logging.info(self.LOGNAME + "Let's get all authorized group services from response")
        parser = etree.XMLParser(recover=True)
        xml = xml.encode('utf-8').replace("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>", "")
        tree = etree.fromstring(xml, parser=parser)
        section_element = tree.xpath("//groupServicesAuthorizationTable")
        services_xml = etree.tostring(section_element[0])
        all_services = self.get_xml_param_all_value(services_xml, ".//row/col[1]")
        auth_status = self.get_xml_param_all_value(services_xml, ".//row/col[2]")
        for service, status in zip(all_services, auth_status):
            if status == "true":
                services.append(service)
        return services

    def check_collaboratebridge_serviceid(self, xml,serviceid):
        serviceids=[]
        logging.info(self.LOGNAME + "Let's get all authorized collaborate bridge from response")
        parser = etree.XMLParser(recover=True)
        xml = xml.encode('utf-8').replace("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>", "")
        tree = etree.fromstring(xml, parser=parser)
        section_element = tree.xpath("//collaborateBridgeTable")
        servicesid_xml = etree.tostring(section_element[0])
        all_servicesid = self.get_xml_param_all_value(servicesid_xml, ".//row/col[1]")
        for i in all_servicesid:
            serviceids.append(i)
        if serviceid in serviceids:
            pass
        else:
            raise Exception('Collaborate bridge is not created')
        return serviceids
    
    def get_all_authorized_user_services(self, xml):
        services = []
        logging.info(self.LOGNAME + "Let's get all authorized group services from response")
        parser = etree.XMLParser(recover=True)
        xml = xml.encode('utf-8').replace("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>", "")
        tree = etree.fromstring(xml, parser=parser)
        section_element = tree.xpath("//userServicesAuthorizationTable")
        services_xml = etree.tostring(section_element[0])
        all_services = self.get_xml_param_all_value(services_xml, ".//row/col[1]")
        auth_status = self.get_xml_param_all_value(services_xml, ".//row/col[2]")
        for service, status in zip(all_services, auth_status):
            if status == "true":
                services.append(service)
        return services

    def get_xml_param_all_value(self, xml, file_tag):
        parser = etree.XMLParser(recover=True)
        # xml = xml.encode('utf-8').replace("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>", "")
        tree = etree.fromstring(xml, parser=parser)
        pretty_values = []
        values = tree.xpath(file_tag)
        for value in values:
            pretty_values.append(value.text)
        return pretty_values

    # Get complete list of numbers assigned to group with expanded ranges
    # Param False | True activatedOnly returns all numbers or only activated numbers
    def get_numbers_assigned_to_group(self, ent_id, group_id, activatedOnly=False):
        response = self.GroupDnGetAssignmentListRequest(ent_id, group_id)
        logging.info(self.LOGNAME + "Let's get all dNs assigned to group")
        values = []
        # get single  numbers (not ranges) assigned to group in e.164
        single_numbers_e164 = re.findall(r"<row><col>(\+\d+-)(\d+)</col>.*?<col>(false|true)</col></row>", response)
        for num in single_numbers_e164:

            if activatedOnly:
                # num[2] corresponds to 'activated' column in response
                if num[2] == 'true':
                    values.append(num[0] + num[1])
            else:
                values.append(num[0] + num[1])

        # get ranges of numbers in e.164 format, assigned to group
        ranges = re.findall(r"<row><col>(\+\d+-\d+)\s+-\s+(\+\d+-\d+)</col>.*?<col>(false|true)</col></row>", response)
        for rng in ranges:
            rstart = rng[0]
            rend = rng[1]
            (ccode1, num1) = re.split('-', rstart)
            (ccode2, num2) = re.split('-', rend)
            tmpnums = range(int(num1), int(num2) + 1)
            for num in tmpnums:
                if activatedOnly:
                    # rng[2] corresponds to 'activated' column in response
                    if rng[2] == 'true':
                        values.append(ccode1 + '-' + str(num))
                else:
                    values.append(ccode1 + '-' + str(num))

        return values

    def check_number_is_assigned_to_group(self, ent_id, group_id, number, country_code, assigned=True,
                                          activatedOnly=False):
        if re.match(r'\+\d+-', number):
            ccode = ''
        else:
            ccode = '+' + country_code + '-'
        number = ccode + number

        numbers = self.get_numbers_assigned_to_group(ent_id, group_id, activatedOnly)

        if assigned:
            if number not in numbers:
                raise Exception("Number '" + number + "' is not assigned to group " + group_id)
            else:
                return True
        else:
            if number in numbers:
                raise Exception("Number '" + number + "' is assigned to group " + group_id)
            else:
                return True

    def add_new_group_tn(self, ent_id, group_id, number):
        self.ServiceProviderDnAddListRequest(ent_id, number)
        self.GroupDnAssignListRequest(ent_id, group_id, number)

    def delete_group_tn(self, ent_id, group_id, number):
        self.GroupDnUnassignListRequest(ent_id, group_id, number)
        self.ServiceProviderDnDeleteListRequest(ent_id, number)

    def get_users_on_system_device(self, system_device_name):
        data = self.SystemAccessDeviceGetUserListRequest(system_device_name)
        result = re.findall(r"<col>(\w+)<\/col><col>\w+<\/col><col>Primary<\/col>", data)

        return result

    def get_users_in_group(self, ent, grp):
        data = self.UserGetListInGroupRequest(ent, grp)
        table = self.get_xml_section_content(data, "//userTable")
        users = self.get_xml_param_all_value(table, ".//row/col[2]")
        return users

    def get_device_types(self):
        data = self.SystemDeviceTypeGetAvailableListRequest19()
        # all_devices = re.findall(r"<deviceType>(.+)<\/deviceType>", data)
        table = self.get_xml_section_content(data, "//command")
        all_devices = self.get_xml_param_all_value(table, ".//deviceType")
        return all_devices

    def get_device_names(self, device_type):
        data = self.SystemAccessDeviceGetAllRequest(device_type)
        table = self.get_xml_section_content(data, "//accessDeviceTable")
        all_devices = self.get_xml_param_all_value(table, ".//row/col[4]")
        return all_devices

    def get_devices_data(self, device_type):
        data = self.SystemAccessDeviceGetAllRequest(device_type)
        all_devices = []
        try:
            table = self.get_xml_section_content(data, "//accessDeviceTable")
            all_device_names = self.get_xml_param_all_value(table, ".//row/col[4]")
            all_device_ents = self.get_xml_param_all_value(table, ".//row/col[1]")
            all_device_groups = self.get_xml_param_all_value(table, ".//row/col[3]")
            for i in range(len(all_device_names)):
                all_devices.append((all_device_ents[i], all_device_groups[i], all_device_names[i]))
        except:
            print(device_type.encode("UTF-8"))
        return all_devices

    def check_device_tags_for_loki(self, data):
        table = self.get_xml_section_content(data, "//deviceCustomTagsTable")
        all_tag_names = self.get_xml_param_all_value(table, ".//row/col[1]")
        bad_tags = []
        for i in all_tag_names:
            if "loki" in i.lower():
                scr_msg = "Loki word is in the tagname: " + i
                logging.error(scr_msg)
                bad_tags.append(i)
        return bad_tags

    # If you want to retrieve only True or False just set raiseex to False.
    def parse_bwks_response(self, response, look_for, raiseex=True, is_exist=True):
        logging.info(self.LOGNAME + "Let's verify that response contains : " + look_for)
        logging.debug(self.LOGNAME + "Response to parse is : " + str(response))
        if look_for in str(response):
            if not is_exist and raiseex:
                logging.error("String '" + look_for + "' is found in response")

                raise Exception("String '" + look_for + "' is found in response " + response)
            elif is_exist:
                logging.debug(self.LOGNAME + "Success! Response contains " + look_for)

            return True
        else:
            if is_exist and raiseex:
                logging.error("String '" + look_for + "' is not found in response")

                raise Exception("String '" + look_for + "' is not found in response " + response)
            elif not is_exist:
                logging.info(self.LOGNAME + "Success! Response doesn`t contain " + look_for)

                return False

    def parse_bwks_response_regular_expression(self, response, reg_expr, raiseex=True, is_exist=True):
        logging.info(self.LOGNAME + "Let's verify that response contains : " + reg_expr)
        logging.debug(self.LOGNAME + "Response to parse is : " + str(response))
        result = re.findall(reg_expr, response)
        if result:
            if not is_exist and raiseex:
                logging.error("String '" + reg_expr + "' is found in response")
                raise Exception("String '" + reg_expr + "' is found in response")
            elif is_exist:
                logging.debug(self.LOGNAME + "Success! Response contains " + reg_expr)
            return True
        else:
            if is_exist and raiseex:
                logging.error("String '" + reg_expr + "' is not found in response")
                raise Exception("String '" + reg_expr + "' is not found in response")
            elif not is_exist:
                logging.info(self.LOGNAME + "Success! Response doesn`t contain " + reg_expr)
                return False

    
    def UserCustomRingbackUserGetCriteriaRequest20(self,user_id,criteria_name):
        logging.info("Sending UserCustomRingbackUserGetCriteriaRequest20 for %s" %criteria_name)
        reqst = """
        <userId>"""+user_id+"""</userId>
        <criteriaName>""" + criteria_name + """</criteriaName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserCustomRingbackUserGetCriteriaRequest20", req)
        response = self.__send_request(request)
        
        return response
    
      
    def UserCustomRingbackUserGetCriteriaRequest21(self,user_id,criteria_name):
        logging.info("Sending UserCustomRingbackUserGetCriteriaRequest21 for %s" %criteria_name)
        reqst = """
        <userId>"""+user_id+"""</userId>
        <criteriaName>""" + criteria_name + """</criteriaName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserCustomRingbackUserGetCriteriaRequest21", req)
        response = self.__send_request(request)
        
        return response
    
    def UserCustomRingbackUserDeleteCriteriaRequest(self,user_id,criteria_name):
        logging.info("Sending UserCustomRingbackUserDeleteCriteriaRequest for  %s" %criteria_name)
        reqst = """
        <userId>"""+user_id+"""</userId>
        <criteriaName>""" + criteria_name + """</criteriaName>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserCustomRingbackUserDeleteCriteriaRequest", req)
        response = self.__send_request(request)
        
        return response
    
    def UserCustomRingbackUserAddCriteriaRequest20(self,user_id,criteria_name,phone):
        logging.info("Sending UserCustomRingbackUserAddCriteriaRequest20 for %s" %criteria_name)
        reqst = """
        <userId>"""+user_id+"""</userId>
        <criteriaName>""" + criteria_name + """</criteriaName>
        <blacklisted>false</blacklisted>
        <fromDnCriteria>
        <fromDnCriteriaSelection>Any</fromDnCriteriaSelection>
        <includeAnonymousCallers>false</includeAnonymousCallers>
        <includeUnavailableCallers>false</includeUnavailableCallers>
        <phoneNumber>""" +phone + """</phoneNumber>
        </fromDnCriteria>
        <audioSelection>Default</audioSelection>
        <videoSelection>Default</videoSelection>
        <callWaitingAudioSelection>Default</callWaitingAudioSelection>
        <callWaitingVideoSelection>Default</callWaitingVideoSelection>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserCustomRingbackUserAddCriteriaRequest20", req)
        response = self.__send_request(request)
        
        return response
    
       
    def UserCustomRingbackUserGetCriteriaListRequest(self,user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve custom criteria list '%s'" % user_id)
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserCustomRingbackUserGetCriteriaListRequest", req)
        response = self.__send_request(request)
        return response
    
    def UserCustomRingbackUserCriteriaName(self,user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve custom criteria list name '%s'" % user_id)
        response=self.UserCustomRingbackUserGetCriteriaListRequest(user_id)
        table = self.get_xml_section_content(response, "//criteriaTable")
        all_names = self.get_xml_param_all_value(table, ".//row/col[2]")
        return all_names
    
    def UserCustomRingbackUserCriteriaState(self,user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve custom criteria list state'%s'" % user_id)
        response=self.UserCustomRingbackUserGetCriteriaListRequest(user_id)
        table = self.get_xml_section_content(response, "//criteriaTable")
        all_states = self.get_xml_param_all_value(table, ".//row/col[1]")
        return all_states
    
    def UserCustomRingbackUserCriteriaToPhoneNumbers(self,user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to retrieve custom criteria list state'%s'" % user_id)
        response=self.UserCustomRingbackUserGetCriteriaListRequest(user_id)
        table = self.get_xml_section_content(response, "//criteriaTable")
        all_phones = self.get_xml_param_all_value(table, ".//row/col[4]")
        return all_phones
    
    def EntSACrequest(self, ent_id,):
        logging.info(
            self.LOGNAME + "Send request to BWKS to retrieve Enterprise SAC session values:'" + ent_id )
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("ServiceProviderSessionAdmissionControlGetRequest", req)
        response = self.__send_request(request)
        return response
    
    def GrpSACrequest(self, ent_id, grp_id):
        logging.info(
            self.LOGNAME + "Send request to BWKS to retrieve Group SAC session values:'" + ent_id )
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + grp_id + """</groupId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupSessionAdmissionControlGetRequest", req)
        response = self.__send_request(request)
        return response
    
    def UserPreAlertingAnnouncementRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to display User PreAlerting Announcements")
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserPreAlertingAnnouncementGetRequest20", req)
        response = self.__send_request(request)
        return response 
    
    def UserCallRecordingRequest20(self, user_id):
        reqst = """
        <userId>""" + user_id + """</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserCallRecordingGetRequest20", req)
        response = self.__send_request(request)
        return response 
    

    def UserExecutiveGetAssistantRequest(self, user_id):
        reqst = """
        <userId>"""+ user_id +"""</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserExecutiveGetAssistantRequest", req)
        response = self.__send_request(request)
        return response
    
    def UserPreAlertingAnnouncementCriteriaAddRequest(self, user_id, criteria_name):
        logging.info(self.LOGNAME + "Send request to BWKS to Add User PreAlerting Announcements Criteria")
        reqst = """
        <userId>""" + user_id + """</userId>
        <criteriaName>""" + criteria_name + """</criteriaName>
        <blacklisted>false</blacklisted>
        <fromDnCriteria>
          <fromDnCriteriaSelection>Any</fromDnCriteriaSelection>
          <includeAnonymousCallers>false</includeAnonymousCallers>
          <includeUnavailableCallers>false</includeUnavailableCallers>
        </fromDnCriteria>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserPreAlertingAnnouncementAddCriteriaRequest", req)
        response = self.__send_request(request)
        return response 
    
    def GroupMeetMeConferencingAddInstanceRequest19_2(self, ent_id, group_id, service_id, host=""):
        logging.info(
            self.LOGNAME + "Send request to BWKS to Add Meet-me conferencing: " + service_id + "to group: " + ent_id + ":" + group_id)
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <serviceUserId>""" + service_id + host + """</serviceUserId>
        <serviceInstanceProfile>
          <name>""" + service_id + """</name>
          <callingLineIdLastName>""" + service_id + """</callingLineIdLastName>
          <callingLineIdFirstName>""" + service_id + """</callingLineIdFirstName>
          <language>English</language>
          <timeZone>America/New_York</timeZone>
        </serviceInstanceProfile>
        <allocatedPorts>
        <quantity>0</quantity>
        </allocatedPorts>
        <securityPinLength>6</securityPinLength>
        <allowIndividualOutDial>true</allowIndividualOutDial>
        <playWarningPrompt>false</playWarningPrompt>
        <conferenceEndWarningPromptMinutes>10</conferenceEndWarningPromptMinutes>
        <enableMaxConferenceDuration>false</enableMaxConferenceDuration>
        <maxConferenceDurationMinutes>
          <hours>3</hours>
          <minutes>0</minutes>
        </maxConferenceDurationMinutes>
        <maxScheduledConferenceDurationMinutes>
          <hours>23</hours>
          <minutes>45</minutes>
        </maxScheduledConferenceDurationMinutes>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupMeetMeConferencingAddInstanceRequest19", req)
        response = self.__send_request(request)
        return response
    
    def GroupBroadWorksAnywhereAddInstanceRequest_2(self, ent_id, group_id, aa_data):
        logging.info(self.LOGNAME + "Send request to BWKS to add Broadworks Anywhere: " + aa_data['ba_name'])
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <serviceUserId>""" + aa_data['ba_id'] + """</serviceUserId>
            <serviceInstanceProfile>
                <name>""" + aa_data['ba_name'] + """</name>
                <callingLineIdLastName>""" + aa_data['ba_lname'] + """</callingLineIdLastName>
                <callingLineIdFirstName>""" + aa_data['ba_fname'] + """</callingLineIdFirstName>
                <language>English</language>
                <timeZone>America/New_York</timeZone>
            </serviceInstanceProfile>
        <broadWorksAnywhereScope>Group</broadWorksAnywhereScope>
        <promptForCLID>Prompt When Not Available</promptForCLID>
        <silentPromptMode>false</silentPromptMode>
        <promptForPasscode>false</promptForPasscode>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupBroadWorksAnywhereAddInstanceRequest", req)
        response = self.__send_request(request)
        return response
    
    def GroupGroupPagingAddInstanceRequest(self, ent_id, group_id, gp_data):
        logging.info(self.LOGNAME + "Send request to BWKS to add Group Paging: " + gp_data['gp_name'])
        reqst = """
        <serviceProviderId>""" + ent_id + """</serviceProviderId>
        <groupId>""" + group_id + """</groupId>
        <serviceUserId>""" + gp_data['gp_id'] + """</serviceUserId>
            <serviceInstanceProfile>
                <name>""" + gp_data['gp_name'] + """</name>
                <callingLineIdLastName>""" + gp_data['gp_lname'] + """</callingLineIdLastName>
                <callingLineIdFirstName>""" + gp_data['gp_fname'] + """</callingLineIdFirstName>
                <language>English</language>
                <timeZone>America/New_York</timeZone>
            </serviceInstanceProfile>
        <confirmationToneTimeoutSeconds>1</confirmationToneTimeoutSeconds>
        <deliverOriginatorCLIDInstead>false</deliverOriginatorCLIDInstead>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("GroupGroupPagingAddInstanceRequest", req)
        response = self.__send_request(request)
        return response
    
    def UserExecutiveModifyAssistantRequest(self, user_id, asst_id):
        logging.info(self.LOGNAME + "Send request to BWKS to add Executive assistant")
        reqst = """
        <userId>"""+ user_id +"""</userId>
        <allowOptInOut>false</allowOptInOut>
        <assistantUserIdList>
          <userId>""" + asst_id + """</userId>
        </assistantUserIdList>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserExecutiveModifyAssistantRequest", req)
        response = self.__send_request(request)
        return response
    
    def UserExecutiveAssistantGetRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get Executive assistant")
        reqst = """
        <userId>"""+ user_id +"""</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserExecutiveAssistantGetRequest", req)
        response = self.__send_request(request)
        return response
    
    def UserExecutiveGetFilteringRequest(self, user_id):
        logging.info(self.LOGNAME + "Send request to BWKS to get Executive assistant Filtering settings")
        reqst = """
        <userId>"""+ user_id +"""</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserExecutiveGetFilteringRequest", req)
        response = self.__send_request(request)
        return response
    
    def UserExecutiveGetScreeningAlertingRequest(self, user_id):    
        logging.info(self.LOGNAME + "Send request to BWKS to get Executive assistant Screening settings")
        reqst = """
        <userId>"""+ user_id +"""</userId>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserExecutiveGetScreeningAlertingRequest", req)
        response = self.__send_request(request)
        return response
    
    def UserModifywithdepRequest17sp4(self,user_data):
        logging.info(self.LOGNAME + "Send request to BWKS to get modify department fo user")
        reqst = """
        <userId>"""+ user_data["user_id"] +"""</userId>

    <lastName>"""+ user_data["user_id"]+"""</lastName>
    <firstName>"""+ user_data["user_id"]+"""</firstName>
    <callingLineIdLastName>"""+ user_data["user_id"]+"""</callingLineIdLastName>
    <callingLineIdFirstName>"""+ user_data["user_id"]+"""</callingLineIdFirstName>
    <nameDialingName xsi:nil="true"/>
    <department xsi:type="GroupDepartmentKey">
      <serviceProviderId>""" + user_data['depServiceProviderId'] + """</serviceProviderId>
                <groupId>""" + user_data['depGroupId'] + """</groupId>
                <name>""" + user_data['depName'] + """</name>
    </department>
    <language>English</language>
    <timeZone>America/New_York</timeZone>
    <title xsi:nil="true"/>
    <pagerPhoneNumber xsi:nil="true"/>
    <mobilePhoneNumber xsi:nil="true"/>
    <emailAddress xsi:nil="true"/>
    <yahooId xsi:nil="true"/>
    <addressLocation xsi:nil="true"/>
    <address>
      <addressLine1 xsi:nil="true"/>
      <addressLine2 xsi:nil="true"/>
      <city xsi:nil="true"/>
      <stateOrProvince xsi:nil="true"/>
      <zipOrPostalCode xsi:nil="true"/>
      <country xsi:nil="true"/>
    </address>
    <networkClassOfService>MIA NCOS</networkClassOfService>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserModifyRequest17sp4", req)
        response = self.__send_request(request)
        return response

    def UserModifyRequest22(self, usr_id, usr_phone, usr_extn, device_type, usr_linePort):
        logging.info(self.LOGNAME+"send request to BKWS to modify user")
        reqst = """
        <userId>""" + usr_id + """</userId>
        <phoneNumber>""" + usr_phone + """</phoneNumber>
        <extension>""" + usr_extn + """</extension>
        <sipAliasList xsi:nil="true" />
        <endpoint>
        <accessDeviceEndpoint>
         <accessDevice>
          <deviceLevel>Group</deviceLevel>
          <deviceName>"""+ device_type +"""</deviceName>
         </accessDevice>
         <linePort>""" + usr_linePort + """</linePort>
         <contactList xsi:nil="true" />
        </accessDeviceEndpoint>
        </endpoint>
        """
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserModifyRequest22", req)
        response = self.__send_request(request)
        return response
    
    def SystemSIPDeviceTypeDeleteRequest(self,profile):
        logging.info(self.LOGNAME+"send request to BKWS to delete device profile type")
        reqst="""
        <deviceType>"""+profile+"""</deviceType>
        """ 
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemSIPDeviceTypeDeleteRequest", req)
        response = self.__send_request(request)
        return response
    
    def SystemAccessDeviceAddRequest2(self,device_data):
        logging.info(self.LOGNAME+"send request to BKWS to add device ")
        reqst="""
        <deviceName>"""+device_data['deviceName']+"""</deviceName>
        <deviceType>"""+device_data['deviceType']+"""</deviceType>
        <protocol>SIP 2.0</protocol>
        <netAddress>12.12.12.12</netAddress>
        <transportProtocol>Unspecified</transportProtocol>"""
        
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemAccessDeviceAddRequest", req)
        response = self.__send_request(request)
        return response
    
    def SystemAccessDeviceDeleteRequest(self,devicename):
        logging.info(self.LOGNAME+"send request to BKWS to delete device ")
        reqst="""
        <deviceName>"""+devicename+"""</deviceName>"""
        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("SystemAccessDeviceDeleteRequest", req)
        response = self.__send_request(request)
        return response

        
    def UserCallRecordingModifyRequest(self,USERID, RECORDINGOPTION, PAUSERESUMENOTIFICATION,
                                       ENABLECALLRECORDINGANNOUNCEMENT, ENABLERECORDCALLREPEATWARNINGTONE,
                                       RECORDCALLREPEATWARNINGTONETIMERSECONDS, ENABLEVOICEMAILRECORDING, MEDIA_STREAM):
        logging.info(self.LOGNAME+"send request to BKWS to modify call recording for user")
        reqst="""
        <userId>"""+USERID+"""</userId>
        <recordingOption>"""+RECORDINGOPTION+"""</recordingOption>
        <pauseResumeNotification>"""+PAUSERESUMENOTIFICATION+"""</pauseResumeNotification>
        <enableCallRecordingAnnouncement>"""+ENABLECALLRECORDINGANNOUNCEMENT+"""</enableCallRecordingAnnouncement>
        <enableRecordCallRepeatWarningTone>"""+ENABLERECORDCALLREPEATWARNINGTONE+"""</enableRecordCallRepeatWarningTone>
        <recordCallRepeatWarningToneTimerSeconds>"""+RECORDCALLREPEATWARNINGTONETIMERSECONDS+"""</recordCallRepeatWarningToneTimerSeconds>
        <enableVoiceMailRecording>"""+ENABLEVOICEMAILRECORDING+"""</enableVoiceMailRecording>
        <mediaStream>"""+MEDIA_STREAM+"""</mediaStream>"""

        req = reqst.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        request = self._generate_request_body("UserCallRecordingModifyRequest", req)
        response = self.__send_request(request)
        return response


