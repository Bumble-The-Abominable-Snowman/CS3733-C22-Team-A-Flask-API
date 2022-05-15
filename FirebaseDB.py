from pprint import pprint

from firebase_admin import credentials
from firebase_admin import firestore
import firebase_admin
import pika
import sys


class DB:
    LOCATIONS = "db-locations"
    EQUIPMENT = "db-equipment"
    MEDICINE = "db-medicine"

    EMPLOYEE = "db-employee"
    # EMPLOYEE_ADMIN = "db-employee-admin"
    # EMPLOYEE_STAFF = "db-employee-staff"
    # EMPLOYEE_NURSE = "db-employee-nurse"
    # EMPLOYEE_DOCTOR = "db-employee-doctor"
    # EMPLOYEE_AIDE = "db-employee-aide"
    # EMPLOYEE_CUSTODIAN = "db-employee-custodian"
    # EMPLOYEE_SECURITY = "db-employee-security"
    # EMPLOYEE_RELIGIOUS = "db-employee-religious"
    # EMPLOYEE_MAINTENANCE = "db-employee-maintenance"
    # EMPLOYEE_LAUNDRY = "db-employee-laundry"
    # EMPLOYEE_LANGUAGE = "db-employee-language"
    # EMPLOYEE_FOOD = "db-employee-food"
    # EMPLOYEE_COURIER = "db-employee-courier"
    # EMPLOYEE_LIST = [EMPLOYEE_ADMIN, EMPLOYEE_STAFF, EMPLOYEE_NURSE, EMPLOYEE_DOCTOR, EMPLOYEE_AIDE, EMPLOYEE_CUSTODIAN,
    #                  EMPLOYEE_SECURITY, EMPLOYEE_RELIGIOUS, EMPLOYEE_MAINTENANCE, EMPLOYEE_LAUNDRY, EMPLOYEE_LANGUAGE,
    #                  EMPLOYEE_FOOD, EMPLOYEE_COURIER]

    SR = "db-sr"
    # SR_EQUIPMENT_DELIVERY = "sr-equipment-delivery"
    # SR_FOOD_DELIVERY = "sr-food-delivery"
    # SR_MEDICINE_DELIVERY = "sr-medicine-delivery"
    # SR_FLORAL_DELIVERY = "sr-floral-delivery"
    # SR_SANITATION = "sr-sanitation"
    # SR_MAINTENANCE = "sr-maintenance"
    # SR_LAUNDRY = "sr-laundry"
    # SR_GIFT_DELIVERY = "sr-gift-delivery"
    # SR_LANGUAGE = "sr-language"
    # SR_CONSULTATION = "sr-consultation"
    # SR_RELIGIOUS = "sr-religious"
    # SR_SECURITY = "sr-security"


class FirebaseDB:

    def __init__(self):
        cred = credentials.Certificate("cs3733-teama-firebase-adminsdk-dgx19-50b0c41f75.json")
        firebase_admin.initialize_app(cred)

        self.db = firestore.client()

    def read_entry(self, collection_name: str, entry_id: str):
        return self.db.collection(collection_name).document(entry_id).get().to_dict()

    def read_all_entries(self, collection_name: str):
        entries = list()
        for entry in self.db.collection(collection_name).stream():
            entries.append(entry.to_dict())
        return entries

    def add_entry(self, collection_name: str, entry_id: str, data: dict):
        self.db.collection(collection_name).document(entry_id).set(data)

    def update_entry(self, collection_name: str, entry_id: str, data: dict):
        self.db.collection(collection_name).document(entry_id).set(data)

    def delete_entry(self, collection_name: str, entry_id: str):
        self.db.collection(collection_name).document(entry_id).delete()

    # locations
    def read_location_entry(self, entry_id: str):
        return self.read_entry(DB.LOCATIONS, entry_id)

    def read_all_location_entries(self):
        return self.read_all_entries(DB.LOCATIONS)

    def add_location_entry(self, data: dict):
        pprint(data)
        self.add_entry(DB.LOCATIONS, data["node_id"], data)

    def update_location_entry(self, data: dict):
        self.add_entry(DB.LOCATIONS, data["node_id"], data)

    def delete_location_entry(self, data: dict):
        self.delete_entry(DB.LOCATIONS, data["node_id"])

    # equipment
    def read_equipment_entry(self, entry_id: str):
        return self.read_entry(DB.EQUIPMENT, entry_id)

    def read_all_equipment_entries(self):
        return self.read_all_entries(DB.EQUIPMENT)

    def add_equipment_entry(self, data: dict):
        self.add_entry(DB.EQUIPMENT, data["equipment_id"], data)

    def update_equipment_entry(self, data: dict):
        self.add_entry(DB.EQUIPMENT, data["equipment_id"], data)

    def delete_equipment_entry(self, data: dict):
        self.delete_entry(DB.EQUIPMENT, data["equipment_id"])

    # medicine
    def read_medicine_entry(self, entry_id: str):
        return self.read_entry(DB.MEDICINE, entry_id)

    def read_all_medicine_entries(self):
        return self.read_all_entries(DB.MEDICINE)

    def add_medicine_entry(self, data: dict):
        self.add_entry(DB.MEDICINE, data["medicine_id"], data)

    def update_medicine_entry(self, data: dict):
        self.add_entry(DB.MEDICINE, data["medicine_id"], data)

    def delete_medicine_entry(self, data: dict):
        self.delete_entry(DB.MEDICINE, data["medicine_id"])

    # employee
    def read_employee_entry(self, entry_id: str):
        return self.read_entry(DB.EMPLOYEE, entry_id)

    def read_all_employee_entries(self, ):
        return self.read_all_entries(DB.EMPLOYEE)

    def add_employee_entry(self, data: dict):
        self.add_entry(DB.EMPLOYEE, data["employee_id"], data)

    def update_employee_entry(self, data: dict):
        self.add_entry(DB.EMPLOYEE, data["employee_id"], data)

    def delete_employee_entry(self, data: dict):
        self.delete_entry(DB.EMPLOYEE, data["employee_id"])

    # service_request
    def read_service_request_entry(self, entry_id: str):
        sr = self.read_entry(DB.SR, entry_id)
        sr_dict: dict = {
            "sr": sr,
            "start-loc": self.read_location_entry(sr["start_location"]),
            "end-loc": self.read_location_entry(sr["end_location"]),
            "emp-req": self.read_employee_entry(sr["employee_requested"]),
            "emp-ass": self.read_employee_entry(sr["employee_assigned"])
        }
        return sr_dict

    def read_all_service_request_entries(self):
        sr_list = self.read_all_entries(DB.SR)
        sr_dict_list = []
        for sr in sr_list:
            sr_dict: dict = {
                "sr": sr,
                "start-loc": self.read_location_entry(sr["start_location"]),
                "end-loc": self.read_location_entry(sr["end_location"]),
                "emp-req": self.read_employee_entry(sr["employee_requested"]),
                "emp-ass": self.read_employee_entry(sr["employee_assigned"])
            }

            sr_dict_list.append(sr_dict)
        pprint(sr_dict_list)
        return sr_dict_list

    def add_service_request_entry(self, data: dict):
        self.add_entry(DB.SR, data["request_id"], data)

    def update_service_request_entry(self, data: dict):
        self.add_entry(DB.SR, data["request_id"], data)

    def delete_service_request_entry(self, data: dict):
        self.delete_entry(DB.SR, data["request_id"])

    def delete_db(self, collection_name: str):
        docs = self.db.collection(collection_name).stream()

        for doc in docs:
            print(f'Deleting doc {doc.id} => {doc.to_dict()}')
            doc.reference.delete()

    def delete_sr_db(self, collection_name: str):
        docs = self.db.collection(DB.SR).stream()

        for doc in docs:
            print(f'Deleting doc {doc.id} => {doc.to_dict()}')
            if doc.to_dict()["table-name"] == collection_name:
                doc.reference.delete()

    def notify_clients(self, data: str):
        connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
        channel = connection.channel()

        channel.exchange_declare(exchange='push_api', exchange_type='topic')
        channel.basic_publish(exchange='push_api',
                                   routing_key='anonymous.info',
                                   body=data)
        print("sent this data: " + data)
        channel.close()

