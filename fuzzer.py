# fuzzer.py
#
# This project makes use of the caringcaribou tool (https://github.com/CaringCaribou/caringcaribou).
# It was constructed using the module template example in caringcaribou.
#
# Steps to add this module to CaringCaribou and run it:
#
# 1. Copy this file to caringcaribou/tool/modules/
#      $ cp module_template.py ../modules/
#
# 2. Go to caringcaribou/tool
#      $ cd ..
#
# 3. Run the following command to run module and show usage instructions:
#      $ ./cc.py module_template -h
#
# Dictionary:
#   1.  "cansend directive"
#       A string that follows the formatting of (for example): "0x123#0xFF 0xFF 0xFF 0xFF".
#       This similar to the arguments one would pass to the cansend command line tool (part of can-util).
import argparse
import random
import string

from can_actions import CanActions, int_from_str_base
from time import sleep


# --- [0]
# Static variable definitions and relevant methods.
# ---


# Converts a given string to its list int representation.
# Uses caringcaribou's int_from_str_base implementation.
#
# @param    line
#           A given string that follows the format of (for example): "0xFF 0xFF 0xFF 0xFF".
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
# A simple static payload to fuzz with.
STATIC_PAYLOAD = "0xFF 0xFF 0xFF 0xFF"


# --- [1]
# Methods that handle random fuzzing.
# ---


def get_random_id():
    arb_id = "0x" + random.choice(LEAD_ID_CHARACTERS)
    for i in range(2):
        arb_id += random.choice(CHARACTERS)
    return arb_id


def get_random_payload(length=4):
    payload = ""
    for i in range(length):
        temp = "0x"
        for j in range(2):
            temp += random.choice(CHARACTERS)
        payload += temp + " "
    return payload


def random_fuzz(static=True, logging=3, length=4):
    # Define a callback function which will handle incoming messages
    def response_handler(msg):
        print("Directive: " + arb_id + "#" + send_msg + " Received Message:" + str(msg))

    log = [None]*(logging)
    counter = 0
    while True:
        arb_id = get_random_id()
        send_msg = (STATIC_PAYLOAD if static else get_random_payload(length))

        with CanActions(int_from_str_base(get_random_id())) as can_wrap:
            # Send the message on the CAN bus and register a callback
            # handler for incoming messages
            can_wrap.send_single_message_with_callback(list_int_from_str_base(send_msg), response_handler)
            # Letting callback handler be active for CALLBACK_HANDLER_DURATION seconds
            sleep(CALLBACK_HANDLER_DURATION)

        counter += 1
        log[counter % logging] = arb_id + send_msg
        if counter == 75:
            print(log)
            break


# --- [2]
# Methods that handle linear fuzzing.
# ---


# Generates a file containing random cansend directives.
#
# @param    filename
#           The file where the cansend directives should be written to.
def gen_random_fuzz_file(filename, size=75):
    fd = open(filename, 'w')
    for i in range(size):
        arb_id = get_random_id()
        payload = get_random_payload()
        fd.write(arb_id + "#" + payload)


# Use a given input file to send can packets.
#
# @param    input_filename
#           The filename of a file containing cansend directives.
def linear_file_fuzz(input_filename, logging=3):
    # Define a callback function which will handle incoming messages
    def response_handler(msg):
        print("Directive: " + line + " Received Message:" + str(msg))

    ifd = open(input_filename, 'r')
    log = [None]*(logging - 1)
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
        if counter == 75:
            print(log)
            break


# --- [3]
# Methods that handle brute force fuzzing.
# ---


def mem_bf_fuzz():
    return


def file_bf_fuzz():
    return


# --- [4]
# Helper methods.
# ---


# Parse a given string that represents a can send directive.
#
# @param    line
#           A given string that represent a can send directive (see dictionary).
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

    :param args: List of arguments
    :return: Argument namespace
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(prog="cc.py fuzzer",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description="A fuzzer for the CAN bus",
                                     epilog="""Example usage: 
                                     cc.py fuzzer -alg random
                                     cc.py fuzzer -alg linear -file example.txt
                                     cc.py fuzzer -alg linear -gen"""
                                     
                                     + """Currently supported algorithms:
                                     * random (static and random payloads)
                                     * linear""")

    parser.add_argument("-alg", type=str, default="random", help="fuzzing algorithm to use")
    parser.add_argument("-static", type=bool, default="True", help="use static payloads")
    parser.add_argument("-file", type=str, help="File containing cansend directives to be used by the fuzzer")
    parser.add_argument("-gen", type=str, help="Generate a cansend directive file to the specified file (with -file)")

    args = parser.parse_args(args)
    return args


# Set up the environment using the passed arguments.
def handle_args(args):
    return args


# --- [5]
# Main methods.
# ---


# A simple testing method to test if caringcaribou and the module work.
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
        random_fuzz()
    except KeyboardInterrupt:
        print("\n\nTerminated by user")
