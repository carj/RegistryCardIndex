import base64
import configparser
import hashlib
import os
import shutil
import sys
import threading
import uuid
import xml.etree.ElementTree
from datetime import datetime
from os import listdir
from os.path import isfile, join
from pathlib import Path
from xml.dom import minidom
from xml.etree.ElementTree import Element, SubElement
from xml.etree.ElementTree import ElementTree
from xml.etree import ElementTree
import boto3
from boto3.s3.transfer import TransferConfig
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import requests
from pyPreservica import EntityAPI
from requests.auth import HTTPBasicAuth
from tinydb import TinyDB, Query
import shortuuid

transfer_config = boto3.s3.transfer.TransferConfig()

number_ingests = 0

KARDEX = "KARDEX"


class ProgressPercentage(object):

    def __init__(self, filename):
        self._filename = filename
        self._size = float(os.path.getsize(filename))
        self._seen_so_far = 0
        self._lock = threading.Lock()

    def __call__(self, bytes_amount):
        # To simplify, assume this is hooked up to a single filename
        with self._lock:
            self._seen_so_far += bytes_amount
            percentage = (self._seen_so_far / self._size) * 100
            sys.stdout.write(
                "\r%s  %s / %s  (%.2f%%)" % (
                    self._filename, self._seen_so_far, self._size,
                    percentage))
            sys.stdout.flush()


def decrypt(key, cypher_text):
    base64_decoded = base64.b64decode(cypher_text)
    aes = cryptography.hazmat.primitives.ciphers.algorithms.AES(key.encode("UTF-8"))
    cipher = Cipher(algorithm=aes, mode=modes.ECB())
    decryptor = cipher.decryptor()
    output_bytes = decryptor.update(base64_decoded) + decryptor.finalize()
    return _unpad(output_bytes.decode("utf-8"))


def make_bitstream(xip, refs_dict, root_path):
    for filename, ref in refs_dict.items():
        bitstream = SubElement(xip, 'Bitstream')
        filenameElement = SubElement(bitstream, "Filename")
        filenameElement.text = filename
        filesize = SubElement(bitstream, "FileSize")
        fullPath = os.path.join(root_path, filename)
        file_stats = os.stat(fullPath)
        filesize.text = str(file_stats.st_size)
        fixities = SubElement(bitstream, "Fixities")
        fixity = SubElement(fixities, "Fixity")
        fixityAlgorithmRef = SubElement(fixity, "FixityAlgorithmRef")
        fixityAlgorithmRef.text = "SHA1"
        fixityValue = SubElement(fixity, "FixityValue")
        sha1 = hashlib.sha1()
        BLOCKSIZE = 65536
        with open(fullPath, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                sha1.update(buf)
                buf = afile.read(BLOCKSIZE)
        fixityValue.text = sha1.hexdigest()


def make_content_objects(xip, refs_dict, io_ref, tag, content_description, content_type):
    for filename, ref in refs_dict.items():
        content_object = SubElement(xip, 'ContentObject')
        ref_element = SubElement(content_object, "Ref")
        ref_element.text = ref
        title = SubElement(content_object, "Title")
        title.text = os.path.splitext(filename)[0]
        description = SubElement(content_object, "Description")
        description.text = content_description
        security_tag = SubElement(content_object, "SecurityTag")
        security_tag.text = tag
        custom_type = SubElement(content_object, "CustomType")
        custom_type.text = content_type
        parent = SubElement(content_object, "Parent")
        parent.text = io_ref


def make_generation(xip, refs_dict, generation_label):
    for filename, ref in refs_dict.items():
        generation = SubElement(xip, 'Generation', {"original": "true", "active": "true"})
        content_object = SubElement(generation, "ContentObject")
        content_object.text = ref
        label = SubElement(generation, "Label")
        if generation_label:
            label.text = generation_label
        else:
            label.text = os.path.splitext(filename)[0]
        effective_date = SubElement(generation, "EffectiveDate")
        effective_date.text = datetime.now().isoformat()
        bitstreams = SubElement(generation, "Bitstreams")
        bitstream = SubElement(bitstreams, "Bitstream")
        bitstream.text = filename
        SubElement(generation, "Formats")
        SubElement(generation, "Properties")


def make_representation(xip, rep_name, rep_type, f, io_ref):
    refs_dict = {}
    representation = SubElement(xip, 'Representation')
    io_link = SubElement(representation, 'InformationObject')
    io_link.text = io_ref
    access_name = SubElement(representation, 'Name')
    access_name.text = rep_name
    access_type = SubElement(representation, 'Type')
    access_type.text = rep_type
    content_objects = SubElement(representation, 'ContentObjects')
    content_object = SubElement(content_objects, 'ContentObject')
    content_object_ref = str(uuid.uuid4())
    content_object.text = content_object_ref
    refs_dict[f] = content_object_ref
    return refs_dict


def _unpad(s):
    return s[:-ord(s[len(s) - 1:])]


def prettify(elem):
    """Return a pretty-printed XML string for the Element.
    """
    rough_string = ElementTree.tostring(elem, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")


def create_asset(xip, security_tag, parent_reference, name, file_name):
    io = SubElement(xip, 'InformationObject')
    ref = SubElement(io, 'Ref')
    ref.text = str(uuid.uuid4())
    asset_id = ref.text
    title = SubElement(io, 'Title')
    title.text = name
    description = SubElement(io, 'Description')
    description.text = file_name
    security = SubElement(io, 'SecurityTag')
    security.text = security_tag
    custom_type = SubElement(io, 'CustomType')
    custom_type.text = ""
    parent = SubElement(io, 'Parent')
    parent.text = parent_reference
    return asset_id


def session_key(server, bucket_name, username, password, aeskey):
    request = requests.get(f"https://{server}/api/admin/locations/upload?refresh={bucket_name}",
                           auth=HTTPBasicAuth(username, password))
    if request.status_code == requests.codes.ok:
        xml_response = str(request.content.decode('utf-8'))
        entity_response = xml.etree.ElementTree.fromstring(xml_response)
        a = entity_response.find('.//a')
        b = entity_response.find('.//b')
        c = entity_response.find('.//c')
        aws_type = entity_response.find('.//type')
        endpoint = entity_response.find('.//endpoint')

        access_key = decrypt(aeskey, a.text)
        secret_key = decrypt(aeskey, b.text)
        session_token = decrypt(aeskey, c.text)
        source_type = decrypt(aeskey, aws_type.text)
        endpoint = decrypt(aeskey, endpoint.text)

        return access_key, secret_key, session_token, source_type, endpoint


def make_dir_if_not_exists(client, name, parent, security_tag):
    ident_key = name

    identifier_prefix = ""
    parent_folder = client.folder(parent)
    identifiers = client.identifiers_for_entity(parent_folder)
    if len(identifiers) == 1:
        identifier = identifiers.pop()
        if identifier[0] == KARDEX:
            identifier_prefix = identifier[1]

    if identifier_prefix != "":
        ident_key = identifier_prefix + "\\" + name

    result = client.identifier(KARDEX, ident_key)
    if result:
        assert len(result) == 1
        entity = result.pop()
        return entity.reference
    else:
        folder = client.create_folder(title=name, description=name, security_tag=security_tag, parent=parent)
        client.add_identifier(folder, KARDEX, ident_key)
        return folder.reference


def ingest_folder(folder, security_tag, folder_references_map, config):
    global number_ingests

    parent_ref = folder_references_map[folder]

    username = config['credentials']['username']
    bucket_name = config['credentials']['bucket']
    password = config['credentials']['password']
    server = config['credentials']['server']
    aeskey = config['credentials']['AESkey']
    file_suffix = config['credentials']['file_suffix']
    export_folder = config['credentials']['export_folder']
    max_ingest = int(config['credentials']['max_ingest'])
    tinydb_path = config['credentials']['tinydb_path']
    content_description = config['credentials']['content_description']

    db = TinyDB(tinydb_path)

    if folder in folder_references_map:

        ## should only compare on folder base name NOT full path
        norm_path = os.path.normpath(folder)
        query = Query()
        result = db.search(query.folder == norm_path)
        if len(result) > 0:
            print("")
            print("Folder " + folder + " has already been processed. Skipping ....")
            return

        print("")
        print("Processing: " + folder + " ...")

        access_key, secret_key, session_token, source_type, endpoint = session_key(server, bucket_name, username,
                                                                                   password,
                                                                                   aeskey)
        xip, all_files = xml_document(security_tag, parent_ref, folder, file_suffix, content_description)

        package_id = shortuuid.ShortUUID().random(length=6)

        top_level_folder = os.path.join(export_folder, package_id)
        os.mkdir(top_level_folder)
        inner_folder = os.path.join(top_level_folder, package_id)
        os.mkdir(inner_folder)
        os.mkdir(os.path.join(inner_folder, "content"))
        metadata_path = os.path.join(inner_folder, "metadata.xml")
        metadata = open(metadata_path, "wt", encoding='utf-8')
        metadata.write(prettify(xip))
        metadata.close()
        if all_files:
            for filename, ref in all_files.items():
                src_file = '\\\\?\\' + os.path.join(folder, filename)
                dst_file = '\\\\?\\' + os.path.normpath(os.path.join(os.path.join(inner_folder, "content"), filename))
                dist = shutil.copyfile(src_file, dst_file)
                assert dst_file == dist
        zip_folder = top_level_folder
        f = shutil.make_archive(top_level_folder, 'zip', zip_folder)
        shutil.rmtree(zip_folder)

        sip_path = top_level_folder + ".zip"

        session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                aws_session_token=session_token)
        s3 = session.resource(service_name="s3")

        upload_key = str(uuid.uuid4())
        s3_object = s3.Object(bucket_name, upload_key)
        metadata = dict()
        metadata['key'] = upload_key
        metadata['name'] = upload_key + ".zip"
        metadata['bucket'] = bucket_name
        metadata['status'] = 'ready'
        metadata['collectionreference'] = parent_ref
        metadata['size'] = str(Path(sip_path).stat().st_size)
        metadata['numberfiles'] = str(len(all_files))
        metadata['createdby'] = "python"

        metadata = {'Metadata': metadata}

        db_data = {"folder": norm_path, "key": upload_key, "parent_ref": parent_ref}

        s3_object.upload_file(sip_path, Callback=ProgressPercentage(sip_path), ExtraArgs=metadata,
                              Config=transfer_config)

        db.insert(db_data)

        os.remove(sip_path)

        number_ingests = number_ingests + 1

        if number_ingests > max_ingest:
            raise SystemExit


def walk_directories(parent_folder, client, parent, security_tag, folder_references_map, file_suffix, config):
    for item in os.listdir(parent_folder):
        child = os.path.normpath(os.path.join(parent_folder, item))
        if os.path.isfile(child):
            if item.endswith(file_suffix):
                ingest_folder(os.path.normpath(parent_folder), security_tag, folder_references_map, config)
                break
        if os.path.isdir(child):
            folder_ref = make_dir_if_not_exists(client, item, parent, security_tag=security_tag)
            folder_references_map[os.path.normpath(child)] = folder_ref
            walk_directories(child, client, folder_ref, security_tag, folder_references_map, file_suffix, config)


def main():
    config = configparser.ConfigParser()
    config.read('credentials.properties')
    username = config['credentials']['username']
    password = config['credentials']['password']
    server = config['credentials']['server']
    folder_root = config['credentials']['folder_root']
    security_tag = config['credentials']['security_tag']
    parent_reference = config['credentials']['parent_reference']
    tenant = config['credentials']['tenant']
    file_suffix = config['credentials']['file_suffix']

    client = EntityAPI(username=username, password=password, tenant=tenant, server=server)

    folder_references_map = dict()
    walk_directories(folder_root, client, parent_reference, security_tag, folder_references_map, file_suffix, config)


def xml_document(security_tag, parent_reference, directory_assets, file_suffix, content_description):
    xip = Element('XIP')
    xip.set('xmlns', 'http://preservica.com/XIP/v6.0')
    all_files = dict()
    asset_files = [f for f in listdir(directory_assets) if isfile(join(directory_assets, f)) and f.endswith(file_suffix)]

    import re

    for name in asset_files:

        if file_suffix.endswith(".pdf"):
            asset_name = name
            index = 0
            for match in re.finditer(re.escape("-"), name):
                start = match.start()
                end = match.end()
                index = index + 1
                if index == 4:
                    asset_name = name[end:].strip()
            asset_name = asset_name.replace(file_suffix, "")
        else:
            asset_name = name

        asset_id = create_asset(xip, security_tag, parent_reference, asset_name, name)

        preservation_refs_dict = make_representation(xip, "Preservation", "Preservation", name, asset_id)
        for key, value in preservation_refs_dict.items():
            all_files[key] = value
        if preservation_refs_dict:
            make_content_objects(xip, preservation_refs_dict, asset_id, security_tag, content_description, "")
        if preservation_refs_dict:
            make_generation(xip, preservation_refs_dict, content_description)
        if preservation_refs_dict:
            make_bitstream(xip, preservation_refs_dict, directory_assets)
    return xip, all_files


if __name__ == '__main__':
    main()
