# module_template.py
#
# This file contains a template for a simple CaringCaribou module.
# The module's entry point is the 'module_main' function.
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

from can_actions import CanActions, int_from_str_base
from time import sleep
import argparse


ARBITRATION_ID_LENGTH = 5
# Number of seconds for callback handler to be active
CALLBACK_HANDLER_DURATION = 0.0001


def build_fuzz_file():
    return


def parse_line(line):
    temp = list()
    pointer = line.find("|")
    temp.append(int_from_str_base(line[0: pointer]))
    temp.append(list_int_from_str_base(line[pointer + 1: len(line)]))
    return temp


def fuzz(input_filename, output_filename):
    # Define a callback function which will handle incoming messages
    def response_handler(msg):
        ofd.write(arb_id + " Sent Message:" + send_msg + " Received Message:" + msg)

    ifd = open(input_filename, 'r')
    ofd = open(output_filename, "a")
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


def list_int_from_str_base(msg):
    temp = msg.split()
    for i in range(len(temp)):
        temp[i] = int_from_str_base(temp[i])
    return temp


def parse_args(args):
    """
    Argument parser for the template module.

    :param args: List of arguments
    :return: Argument namespace
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(prog="cc.py module_template",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description="Descriptive message for the template module",
                                     epilog="""Example usage:
                                     cc.py module_template -arbId 123
                                     cc.py module_template -arbId 0x1FF""")

    parser.add_argument("-arbId", type=str, default="0", help="arbitration ID to use")

    args = parser.parse_args(args)
    return args


def test_module(arbitration_id):
    with CanActions(arbitration_id) as can_wrap:
        can_wrap.send(list_int_from_str_base("0xFF 0xFF 0xFF 0xFF"))
    line = "0x125|0xFF 0xFF 0xFF 0xF0"
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
        #args = parse_args(arg_list)
        # Parse arbitration ID from the arguments (this function resolves both base 10 and hex values)
        #arbitration_id = int_from_str_base(args.arbId)
        # Time to actually do stuff
        test_module(arbitration_id)
        fuzz("input.txt", "output.txt")
    except KeyboardInterrupt:
        print("\n\nTerminated by user")
