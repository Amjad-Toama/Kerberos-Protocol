"""
Handle validation process of files in the system with correct structure and content.
"""

from validators import is_valid_port, is_valid_uuid, is_valid_endpoint, is_valid_name, is_valid_64base_symmetric_key
from pathlib import Path

# *********************** File Validity Constants ************************ #

FILE_CONTENT_AT_LINE = 1    # Each line have no whitespaces, hence it's 1 long token
PORT_FILE_LINES = 1         # Port file lines amount
SRV_FILE_LINES = 2          # Server file lines amount
MSG_FILE_LINES = 4          # Message server lines amount
ME_FILE_LINES = 2           # Me file lines amount


def is_valid_file_extension(filename, expected_extension):
    # check if file extension compatible to the expected one.
    return Path(filename).suffix == expected_extension


def is_valid_file_to_open(filename, mode):
    #  check if file can be open
    try:
        with open(filename, mode):
            return True
    except (FileNotFoundError, PermissionError):
        return False
    except OSError:
        return False


def is_valid_port_file(filename):
    # check port file structure and content.
    # check the extension and to be open.
    if (is_valid_file_extension(filename, ".info")
            and is_valid_file_to_open(filename, "r")):
        # open the file
        with open(filename, "r") as file:
            # read all file content - to check valid file structure
            lines = file.readlines()
            # check lines amount
            if len(lines) != PORT_FILE_LINES:
                return False
            port_str = lines[0].strip().split()
            # check line content amount, and validity of port value
            validity = (len(port_str) == FILE_CONTENT_AT_LINE and is_valid_port(port_str[0]))
            return validity
    return False


def is_valid_srv_file(filename):
    # check srv.info file legibility, and the ability to open
    if (is_valid_file_extension(filename, ".info")
            and is_valid_file_to_open(filename, "r")):
        with open(filename, "r") as file:
            # read all file content - to check valid file structure
            lines = file.readlines()
            # check lines amount
            if len(lines) != SRV_FILE_LINES:
                return False
            # check each line
            for line in lines:
                # check line token amount
                # check endpoint structure
                if ((len(line.strip().split(' ')) != FILE_CONTENT_AT_LINE)
                        or not (is_valid_endpoint(line))):
                    return False
            return True
    return False


def is_valid_msg_file(filename):
    # check msg.ingo file structure and content
    if (is_valid_file_extension(filename, ".info")
            and is_valid_file_to_open(filename, "r")):
        with open(filename, "r") as file:
            # read all file content - to check valid file structure
            lines = file.readlines()
            # check lines amount
            if len(lines) != MSG_FILE_LINES:
                return False
            # 0. endpoint
            if ((len(lines[0].strip().split(' ')) != FILE_CONTENT_AT_LINE)
                    or not (is_valid_endpoint(lines[0].strip()))):
                return False
            # 1. name
            if not is_valid_name(lines[1].strip()):
                return False
            # 2. uuid
            if ((len(lines[2].strip().split(' ')) != FILE_CONTENT_AT_LINE)
                    or not (is_valid_uuid(lines[2].strip()))):
                return False
            # 3. symmetric key base64
            if ((len(lines[3].strip().split(' ')) != FILE_CONTENT_AT_LINE)
                    or not (is_valid_64base_symmetric_key(lines[3].strip()))):
                return False
            return True
    return False


def is_valid_me_info(filename):
    # check me.info file structure and content legibility.
    if (is_valid_file_extension(filename, ".info")
            and is_valid_file_to_open(filename, "r")):
        with open(filename, "r") as file:
            # read all file content - to check valid file structure
            lines = file.readlines()
            # check lines amount
            if len(lines) != ME_FILE_LINES:
                return False
            # 0. name
            if not is_valid_name(lines[0].strip()):
                return False
            # 1. uuid
            if ((len(lines[1].strip().split(' ')) != FILE_CONTENT_AT_LINE)
                    or not (is_valid_uuid(lines[1].strip()))):
                return False
            return True
    return False
