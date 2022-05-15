import re

from FirebaseDB import FirebaseDB, DB
from FlaskAuthWrapper import *

import requests
import constants
from FlaskAppWrapper import FlaskAppWrapper


class FlaskApiHandler:
    def __init__(self, app: Flask, auth: FlaskAuthWrapper):
        self.auth = auth
        self.app = app

        self.app.add_url_rule("/api", "api", self.api)
        self.app.add_url_rule("/api/login", "api/login", self.login)
        self.app.add_url_rule("/api/callback_login", "api/callback_login", self.callback_login)
        self.app.add_url_rule("/api/verification", "api/verification", self.verification)
        self.app.add_url_rule("/api/logout", "api/logout", self.logout)
        self.app.add_url_rule("/api/locations", "api/locations", self.locations, methods=['GET', 'POST'])
        self.app.add_url_rule("/api/equipment", "api/equipment", self.equipment, methods=['GET', 'POST'])
        self.app.add_url_rule("/api/medicine", "api/medicine", self.medicine, methods=['GET', 'POST'])
        self.app.add_url_rule("/api/employees", "api/employees", self.employees, methods=['GET', 'POST'])
        self.app.add_url_rule("/api/service_request", "api/service_request", self.service_request, methods=['GET', 'POST'])

        self.db = FirebaseDB()


    def login(self):
        return self.auth.auth0.authorize_redirect(redirect_uri=url_for('api/callback_login', _external=True, _scheme='https'), audience=constants.AUTH0_AUDIENCE)

    def callback_login(self):
        auth_resp = self.auth.auth0.authorize_access_token()

        resp = self.auth.auth0.get('userinfo')
        userinfo = resp.json()
        pprint(userinfo)

        session[constants.JWT_PAYLOAD] = auth_resp["access_token"]
        session[constants.PROFILE_KEY] = {
            'user_id': userinfo['sub'],
            'name': userinfo['nickname'],
            'picture': userinfo['picture']
        }
        params = {'token': auth_resp["access_token"],
                  'email': userinfo['name']}

        return redirect(url_for('api/verification', _external=True, _scheme='https') + '?' + urlencode(params))

    @FlaskAuthWrapper.requires_auth_session
    def verification(self):

        return render_template('verification.html',
                          userinfo=session[constants.PROFILE_KEY])

    def logout(self):
        session.clear()
        params = {'returnTo': url_for('api/login', _external=True, _scheme='https'), 'client_id': constants.AUTH0_CLIENT_ID}
        return redirect(self.auth.auth0.api_base_url + '/v2/logout?' + urlencode(params))

    @cross_origin(headers=["Content-Type", "Authorization"])
    @FlaskAuthWrapper.requires_auth
    def api(self):
        response = "You are authenticated."
        return jsonify(message=response)

    @cross_origin(headers=["Content-Type", "Authorization"])
    @FlaskAuthWrapper.requires_auth
    def locations(self):
        request_data = dict(request.get_json())
        print(request_data)

        if FlaskAuthWrapper.requires_permission("user-admin") and request_data["metadata"][0]["operation"] == "populate":
            self.db.delete_db(DB.LOCATIONS)
            for entry in request_data["payload"]:
                self.db.add_location_entry(entry)
            self.db.notify_clients("location")
            return jsonify(message="success")

        if FlaskAuthWrapper.requires_permission("read:db-locations"):

            if request_data["metadata"][0]["operation"] == "get":
                return json.dumps(self.db.read_location_entry(request_data["metadata"][0]["node_id"]))
            if request_data["metadata"][0]["operation"] == "getall":
                return json.dumps(self.db.read_all_location_entries())

        if FlaskAuthWrapper.requires_permission("write:db-locations"):

            if request_data["metadata"][0]["operation"] == "add":
                self.db.add_location_entry(request_data["payload"][0])
                self.db.notify_clients("location")
                return jsonify(message="success")
            if request_data["metadata"][0]["operation"] == "update":
                self.db.update_location_entry(request_data["payload"][0])
                self.db.notify_clients("location")
                return jsonify(message="success")
            if request_data["metadata"][0]["operation"] == "delete":
                self.db.delete_location_entry(request_data["payload"][0])
                self.db.notify_clients("location")
                return jsonify(message="success")

        raise AuthError({
            "code": "Unauthorized or wrong operation",
            "description": "You don't have access to this resource"
        }, 403)

    @cross_origin(headers=["Content-Type", "Authorization"])
    @FlaskAuthWrapper.requires_auth
    def equipment(self):
        request_data = dict(request.get_json())

        if FlaskAuthWrapper.requires_permission("user-admin") and request_data["metadata"][0]["operation"] == "populate":
            self.db.delete_db(DB.EQUIPMENT)
            for entry in request_data["payload"]:
                self.db.add_equipment_entry(entry)
            self.db.notify_clients("equipment")
            return jsonify(message="success")

        if FlaskAuthWrapper.requires_permission("read:db-equipment"):

            if request_data["metadata"][0]["operation"] == "get":
                return json.dumps(self.db.read_equipment_entry(request_data["metadata"][0]["equipment_id"]))
            if request_data["metadata"][0]["operation"] == "getall":
                return json.dumps(self.db.read_all_equipment_entries())

        if FlaskAuthWrapper.requires_permission("write:db-equipment"):

            if request_data["metadata"][0]["operation"] == "add":
                self.db.add_equipment_entry(request_data["payload"][0])
                self.db.notify_clients("equipment")
                return jsonify(message="success")
            if request_data["metadata"][0]["operation"] == "update":
                self.db.update_equipment_entry(request_data["payload"][0])
                self.db.notify_clients("equipment")
                return jsonify(message="success")
            if request_data["metadata"][0]["operation"] == "delete":
                self.db.delete_equipment_entry(request_data["payload"][0])
                self.db.notify_clients("equipment")
                return jsonify(message="success")

        raise AuthError({
            "code": "Unauthorized or wrong operation",
            "description": "You don't have access to this resource"
        }, 403)

    @cross_origin(headers=["Content-Type", "Authorization"])
    @FlaskAuthWrapper.requires_auth
    def medicine(self):
        request_data = dict(request.get_json())
        pprint(request_data)

        if FlaskAuthWrapper.requires_permission("user-admin") and request_data["metadata"][0]["operation"] == "populate":
            if request_data["metadata"][0]["table-name"] == "medicine":
                self.db.delete_db(DB.MEDICINE)
                for entry in request_data["payload"]:
                    self.db.add_medicine_entry(entry)
                self.db.notify_clients("medicine")
                return jsonify(message="success")
            if request_data["metadata"][0]["table-name"] == "dosages":
                for entry in self.db.read_all_medicine_entries():
                    entry["dosage_amount"] = ""
                    for dosage_info in request_data["payload"]:
                        if entry["medicine_id"] == dosage_info["medicine_id"]:
                            entry["dosage_amount"] += dosage_info["dosage_amount"] + " "
                    self.db.add_medicine_entry(entry)
                self.db.notify_clients("medicine")
                return jsonify(message="success")

        if FlaskAuthWrapper.requires_permission("read:db-medicine"):

            if request_data["metadata"][0]["operation"] == "get":
                return json.dumps(self.db.read_medicine_entry(request_data["metadata"][0]["medicine_id"]))
            if request_data["metadata"][0]["operation"] == "getall":
                return json.dumps(self.db.read_all_medicine_entries())

        if FlaskAuthWrapper.requires_permission("write:db-medicine"):

            if request_data["metadata"][0]["operation"] == "add":
                self.db.add_medicine_entry(request_data["payload"][0])
                self.db.notify_clients("medicine")
                return jsonify(message="success")
            if request_data["metadata"][0]["operation"] == "update":
                self.db.update_medicine_entry(request_data["payload"][0])
                self.db.notify_clients("medicine")
                return jsonify(message="success")
            if request_data["metadata"][0]["operation"] == "delete":
                self.db.delete_medicine_entry(request_data["payload"][0])
                self.db.notify_clients("medicine")
                return jsonify(message="success")

        raise AuthError({
            "code": "Unauthorized or wrong operation",
            "description": "You don't have access to this resource"
        }, 403)

    @cross_origin(headers=["Content-Type", "Authorization"])
    @FlaskAuthWrapper.requires_auth
    def employees(self):
        request_data = dict(request.get_json())
        entries = []

        if FlaskAuthWrapper.requires_permission("user-admin") and request_data["metadata"][0]["operation"] == "populate":
            self.db.delete_db(DB.EMPLOYEE)
            for entry in request_data["payload"]:
                self.db.add_employee_entry(entry)
            self.db.notify_clients("employee")
            return jsonify(message="success")

        for permission in FlaskAuthWrapper.get_permissions():
            if re.compile("(read|write):db-employee-").match(permission):
                db_table_permission_level = permission.split(":")[0]
                db_table_name = permission.split(":")[1]

                if db_table_permission_level == "read":
                    if request_data["metadata"][0]["operation"] == "getall":
                        emp_db = self.db.read_all_employee_entries()
                        for emp in emp_db:
                            if FlaskAuthWrapper.requires_permission("read:db-employee-" + emp["employee_type"]):
                                entries.append(emp)
                        return json.dumps(entries)

                    if request_data["metadata"][0]["operation"] == "get":
                        emp = self.db.read_employee_entry(request_data["metadata"][0]["employee_id"])
                        if FlaskAuthWrapper.requires_permission("write:db-employee-" + emp["employee_type"]):
                            return json.dumps(emp)
                else:
                    if db_table_permission_level == "write" and not (request_data["metadata"][0]["operation"] in ["get", "getall"]):
                        if ("db-employee-" + request_data["payload"][0]["employee_type"]) == db_table_name:
                            if request_data["metadata"][0]["operation"] == "add":
                                self.db.add_employee_entry(request_data["payload"][0])
                                self.db.notify_clients("employee")
                                return jsonify(message="success")
                            if request_data["metadata"][0]["operation"] == "update":
                                self.db.update_employee_entry(request_data["payload"][0])
                                self.db.notify_clients("employee")
                                return jsonify(message="success")
                            if request_data["metadata"][0]["operation"] == "delete":
                                self.db.delete_employee_entry(request_data["payload"][0])
                                self.db.notify_clients("employee")
                                return jsonify(message="success")

        raise AuthError({
            "code": "Unauthorized or wrong operation",
            "description": "You don't have access to this resource"
        }, 403)

    @cross_origin(headers=["Content-Type", "Authorization"])
    @FlaskAuthWrapper.requires_auth
    def service_request(self):
        request_data = dict(request.get_json())
        pprint(request_data)
        entries = []

        if FlaskAuthWrapper.requires_permission("user-admin") and request_data["metadata"][0]["operation"] == "populate":
            self.db.delete_sr_db(request_data["metadata"][0]["table-name"])
            for entry in request_data["payload"]:
                entry["table-name"] = request_data["metadata"][0]["table-name"]
                self.db.add_service_request_entry(entry)
            self.db.notify_clients("sr")
            return jsonify(message="success")

        for permission in FlaskAuthWrapper.get_permissions():

            if re.compile("(read|write):db-sr-").match(permission):
                db_table_permission_level = permission.split(":")[0]
                db_table_name = permission.split(":")[1]

                if db_table_permission_level == "read":
                    if request_data["metadata"][0]["operation"] == "getall":
                        sr_db = self.db.read_all_service_request_entries()
                        for sr_struct in sr_db:
                            if FlaskAuthWrapper.requires_permission("read:" + sr_struct["sr"]["table-name"]):
                                sr_sr = sr_struct["sr"]
                                sr_sr.pop("table-name")
                                sr_struct["sr"] = sr_sr
                                entries.append(sr_struct)
                        return json.dumps(entries)

                    if request_data["metadata"][0]["operation"] == "get":
                        sr_struct = self.db.read_service_request_entry(request_data["metadata"][0]["request_id"])
                        if FlaskAuthWrapper.requires_permission("read:" + sr_struct["sr"]["table-name"]):
                            return json.dumps(sr_struct)

                else:
                    if db_table_permission_level == "write" and not (request_data["metadata"][0]["operation"] in ["get", "getall"]):
                        if db_table_name == request_data["metadata"][0]["table-name"]:
                            if request_data["metadata"][0]["operation"] == "add":
                                request_data["payload"][0]["table-name"] = db_table_name
                                self.db.add_service_request_entry(request_data["payload"][0])
                                self.db.notify_clients("sr")
                                return jsonify(message="success")
                            if request_data["metadata"][0]["operation"] == "update":
                                request_data["payload"][0]["table-name"] = db_table_name
                                self.db.update_service_request_entry(request_data["payload"][0])
                                self.db.notify_clients("sr")
                                return jsonify(message="success")
                            if request_data["metadata"][0]["operation"] == "delete":
                                self.db.delete_service_request_entry(request_data["payload"][0])
                                self.db.notify_clients("sr")
                                return jsonify(message="success")

        raise AuthError({
            "code": "Unauthorized or wrong operation",
            "description": "You don't have access to this resource"
        }, 403)
