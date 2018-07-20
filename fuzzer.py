# fuzzer.py
#
# Dictionary:
#   1.  "cansend directive"
#       A string that follows the formatting of (for example): "0x123#0xFF 0xFF 0xFF 0xFF".
#       This is similar to the arguments one would pass to the cansend command line tool (part of can-util).
import argparse
import random
import string

from can_actions import CanActions, int_from_str_base
from time import sleep


# --- [0]
# Static variable definitions and relevant methods.
# ---


# Converts a given string to its list int representation.
# Uses CaringCaribou's int_from_str_base implementation.
#
# @param    line
#           A given string that follows the format of (for example): "0xFF 0xFF 0xFF 0xFF".
#
# @return   Returns a list of ints representing the values in the string.
#           For example: [0xFF, 0xFF, 0xFF, 0xFF] (with 0xFF in its int representation).
def list_int_from_str_base(line):
    temp = line.split()
    for i in range(len(temp)):
        temp[i] = int_from_str_base(temp[i])
    return temp


# Number of seconds for callback handler to be active.
CALLBACK_HANDLER_DURATION = 0.0001
# The characters used to generate random ids/payloads.
CHARACTERS = string.hexdigits[0:10] + string.hexdigits[16:22]
# The leading value in a can id is a value between 0 and 7.
LEAD_ID_CHARACTERS = string.digits[0:8]
# A simple static arbitration id to fuzz with.
STATIC_ARB_ID = "0x001"
# A simple static payload to fuzz with.
STATIC_PAYLOAD = "0xFF 0xFF 0xFF 0xFF"


# --- [1]
# Methods that handle random fuzzing.
# ---


# Get a random arbitration id in the format 0xABC.
#
# @return   A random arbitration id in the format 0xABC.
def get_random_id():
    arb_id = "0x" + random.choice(LEAD_ID_CHARACTERS)
    for i in range(2):
        arb_id += random.choice(CHARACTERS)
    return arb_id


# Get a random payload in the format "0xFF " * length.

# @param    length
#           The length of the payload.
#
# @return   A random payload in the format "0xFF " * length.
def get_random_payload(length=4):
    payload = ""
    for i in range(length):
        temp = "0x"
        for j in range(2):
            temp += random.choice(CHARACTERS)
        payload += temp + " "
    return payload


# A simple random id fuzzer algorithm.
# Send random or static CAN messages to random arbitration ids.
# Uses CanActions to send/receive from the CAN bus.
#
# @param    static
#           Use a static CAN message or not.
# @param    logging
#           How many cansend directives must be kept in memory at a time.
# @param    payload
#           Override the static payload with the given payload.
# @param    length
#           The length of the payload, this is used if random payloads are needed.
def random_fuzz(static=True, logging=1, payload=STATIC_PAYLOAD, length=4):
    # Define a callback function which will handle incoming messages
    def response_handler(msg):
        print("Directive: " + arb_id + "#" + send_msg + " Received Message:" + str(msg))

    log = [None]*logging
    counter = 0
    while True:
        arb_id = get_random_id()
        send_msg = (payload if static else get_random_payload(length))

        with CanActions(int_from_str_base(get_random_id())) as can_wrap:
            # Send the message on the CAN bus and register a callback
            # handler for incoming messages
            can_wrap.send_single_message_with_callback(list_int_from_str_base(send_msg), response_handler)
            # Letting callback handler be active for CALLBACK_HANDLER_DURATION seconds
            sleep(CALLBACK_HANDLER_DURATION)

        counter += 1
        log[counter % logging] = arb_id + send_msg


# --- [2]
# Methods that handle linear fuzzing.
# ---


# Generates a file containing random cansend directives.
#
# @param    filename
#           The file where the cansend directives should be written to.
# @param    amount
#           The amount of
def gen_random_fuzz_file(filename, amount=75, static=True, payload=STATIC_PAYLOAD, length=4):
    fd = open(filename, 'w')
    for i in range(amount):
        arb_id = get_random_id()
        payload = (payload if static else get_random_payload(length))
        fd.write(arb_id + "#" + payload + "\n")
    fd.close()


# Use a given input file to send can packets.
# Uses CanActions to send/receive from the CAN bus.
#
# @param    input_filename
#           The filename of a file containing cansend directives.
# @param    logging
#           How many cansend directives must be kept in memory at a time.
#
def linear_file_fuzz(input_filename, logging=1):
    # Define a callback function which will handle incoming messages
    def response_handler(msg):
        print("Directive: " + line + " Received Message:" + str(msg))

    ifd = open(input_filename, 'r')
    log = [None]*logging
    counter = 0
    for line in ifd:
        temp = parse_line(line)
        arb_id = temp[0]
        send_msg = temp[1]

        with CanActions(arb_id) as can_wrap:
            # Send the message on the CAN bus and register a callback
            # handler for incoming messages
            can_wrap.send_single_message_with_callback(send_msg, response_handler)
            # Letting callback handler be active for CALLBACK_HANDLER_DURATION seconds
            sleep(CALLBACK_HANDLER_DURATION)

        counter += 1
        log[counter % logging] = line


# --- [3]
# Methods that handle brute force fuzzing.
# ---


def mem_bf_fuzz():
    return


def file_bf_fuzz():
    return


# noinspection PyUnusedLocal
def format_can_payload(payload):
    result = ""
    for i in range(0, len(payload), 2):
        result += "0x" + payload[i] + payload[i+1] + " "
    result = result[:len(result)-1] + "\n"
    return result


def get_next_bf_payload(last_payload):
    ring = len(last_payload) - 1
    while last_payload[ring] == "F":
        ring -= 1

    i = CHARACTERS.find(last_payload[ring])
    print(CHARACTERS)
    print(i)
    payload = last_payload[:ring] + CHARACTERS[(i+1) % len(CHARACTERS)] + last_payload[ring+1:]

    for ring in range(len(last_payload)):
        payload = payload[:ring] + '0' + payload[ring+1:]

    return payload


def cyclic_bf_fuzz(logging=1):
    print("Cyclic brute force")

    # Define a callback function which will handle incoming messages
    def response_handler(msg):
        print("Directive: " + arb_id + "#" + send_msg + " Received Message:" + str(msg))

    payload = "0" * 16
    log = [None]*logging
    counter = 0
    # manually send first payload
    while payload != "F" * 16:
        payload = get_next_bf_payload(payload)
        arb_id = "0x133"
        send_msg = format_can_payload(payload)

        with CanActions(int_from_str_base(arb_id)) as can_wrap:
            # Send the message on the CAN bus and register a callback
            # handler for incoming messages
            can_wrap.send_single_message_with_callback(list_int_from_str_base(send_msg), response_handler)
            # Letting callback handler be active for CALLBACK_HANDLER_DURATION seconds
            sleep(CALLBACK_HANDLER_DURATION)

        counter += 1
        log[counter % logging] = arb_id + send_msg


# --- [4]
# Methods that handle mutation fuzzing.
# ---


def get_mutated_id(arb_id_bitmap, arb_id):
    if arb_id_bitmap[0]:
        new_arb_id = "0x" + random.choice(LEAD_ID_CHARACTERS)
    else:
        new_arb_id = "0x" + arb_id[2: len(arb_id)]
    for i in range(2):
        if arb_id_bitmap[i+1]:
            new_arb_id += random.choice(CHARACTERS)
        else:
            new_arb_id += arb_id[3+i: 3+i+2]
    return new_arb_id


# noinspection PyUnusedLocal
def get_mutated_payload(payload_bitmap, payload):
    return


# @param    arb_id_bitmap
#           A list where each element is True or False depending on whether or not the hex value at that position
#           in the arb_id is allowed to be mutated.
# noinspection PyUnusedLocal
def mutate_fuzz(arb_id_bitmap, payload_bitmap, arb_id=STATIC_ARB_ID, payload=STATIC_PAYLOAD, logging=1):
    return


# --- [5]
# Helper methods.
# ---


# Parse a given string that represents a can send directive.
#
# @param    line
#           A given string that represent a can send directive (see dictionary).
#
# @return   Returns a list in the following format: [id, message]
#           where id is the target device id and message is the message to be sent.
#           id and message are both in their int representation.
def parse_line(line):
    temp = list()
    pointer = line.find("#")
    temp.append(int_from_str_base(line[0: pointer]))
    temp.append(list_int_from_str_base(line[pointer + 1: len(line)]))
    return temp


def parse_args(args):
    """
    Argument parser for the template module.

    Notes about values of namespace after parsing:
    Arguments that must be converted before -use static, -gen.
    Arguments that can be None: -alg, -file, -payload.

    :param args: List of arguments
    :return: Argument namespace
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(prog="cc.py fuzzer",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description="A fuzzer for the CAN bus",
                                     epilog="""Example usage:
                                     cc.py fuzzer -alg random
                                     cc.py fuzzer -alg linear -gen True -file example.txt"""

                                     + """"\nCurrently supported algorithms:
                                     random - Try out random ids with a random or static payload
                                     linear""")

    # boolean values are initially stored as strings, call to_bool() before use!
    parser.add_argument("-static", type=str, default="True", help="Do not use static payloads (default is True)")
    parser.add_argument("-gen", type=str, default="False",
                        help="Generate a cansend directive file to the file specified with -file "
                             "(used by the linear algorithm)")
    parser.add_argument("-log", type=int, default=1,
                        help="How many cansend directives must be kept in memory at a time (default is 1)")

    parser.add_argument("-alg", type=str, help="What fuzzing algorithm to use")
    parser.add_argument("-file", type=str, help="File containing cansend directives (used by the linear algorithm)")
    parser.add_argument("-payload", type=str, help="Override the static payload with a different payload."
                                                   "Use the following syntax: 0xFF 0xFF 0xFF 0xFF")

    args = parser.parse_args(args)
    return args


# Convert a given string to a boolean.
#
# @return False if value.upper() == "FALSE" or value == "0" or value == "" else True
def to_bool(value):
    return False if value.upper() == "FALSE" or value == "0" or value == "" else True


# Set up the environment using the passed arguments and execute the correct algorithm.
def handle_args(args):
    args.static = to_bool(str(args.static))
    args.gen = to_bool(str(args.gen))
    payload = STATIC_PAYLOAD
    if args.payload is not None:
        payload = args.payload

    if args.alg is None:
        raise NameError
    elif args.alg == "random":
        random_fuzz(args.static, args.log, payload, 8)
        return
    elif args.alg == "linear":
        filename = args.file
        if filename is None:
            raise NameError
        if args.gen:
            gen_random_fuzz_file(filename, 100, args.static, payload, 8)
        linear_file_fuzz(filename, args.log)
        return
    elif args.alg == "mem_bf":
        print("Currently not implemented.")
        return
    elif args.alg == "file_bf":
        print("Currently not implemented.")
        return
    elif args.alg == "mutate":
        print("Currently not implemented.")
        return
    elif args.alg == "cyclic_bf":
        cyclic_bf_fuzz(args.log)
    else:
        raise ValueError


# --- [6]
# Main methods.
# ---


# A simple testing method to test if CaringCaribou and the module work.
def test_module():
    arbitration_id = int_from_str_base("0x000")
    with CanActions(arbitration_id) as can_wrap:
        can_wrap.send(list_int_from_str_base("0xFF 0xFF 0xFF 0xFF"))
    line = "0x125#0xFF 0xFF 0xFF 0xF0"
    temp = parse_line(line)
    with CanActions(temp[0]) as can_wrap:
        can_wrap.send(temp[1])


def module_main(arg_list):
    """
    Module main wrapper. This is the entry point of the module when called by cc.py

    :param arg_list: Module argument list passed by cc.py
    """
    try:
        # Parse arguments
        args = parse_args(arg_list)
        handle_args(args)
    except KeyboardInterrupt:
        print("\n\nTerminated by user")
    except ValueError:
        print("Invalid syntax")
    except NameError:
        print("Not enough arguments specified")
    exit(0)
