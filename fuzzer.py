# fuzzer.py
#
# Dictionary:
#   1.  "cansend directive"
#       A string that follows the formatting of (for example): "123#FFFFFFFF".
#       This is similar to the arguments one would pass to the cansend command line tool (part of can-util).
#   2. "composite cansend directive"
#       A cansend directive split up in its id and payload: [id, payload].

import argparse
import random
import string

from can_actions import CanActions, int_from_str_base
from time import sleep


# --- [0]
# Static variable definitions and generic methods
# ---


# Number of seconds for callback handler to be active.
CALLBACK_HANDLER_DURATION = 0.0001
# The characters used to generate random ids/payloads.
CHARACTERS = string.hexdigits[0:10] + string.hexdigits[16:22]
# The leading value in a can id is a value between 0 and 7.
LEAD_ID_CHARACTERS = string.digits[0:8]
# An arbitration id consisting only of zeros.
ZERO_ARB_ID = "0" * 3
# A payload consisting only of zeros.
ZERO_PAYLOAD = "0" * 16
test_arb_id_bitmap = [True, False, False]
test_payload_bitmap = [False, False, False, False, True, True, True, True]


def directive_send(arb_id, payload, response_handler):
    """
    Sends a cansend directive.

    :param arb_id: The destination arbitration id.
    :param payload: The payload to be sent.
    :param response_handler: The callback handler that needs to be called when a response message is received.
    """
    arb_id = '0x' + arb_id
    send_msg = payload_to_str_base(payload)
    with CanActions(int_from_str_base(arb_id)) as can_wrap:
        # Send the message on the CAN bus and register a callback
        # handler for incoming messages
        can_wrap.send_single_message_with_callback(list_int_from_str_base(send_msg), response_handler)
        # Letting callback handler be active for CALLBACK_HANDLER_DURATION seconds
        sleep(CALLBACK_HANDLER_DURATION)


def write_directive_to_file(filename, arb_id, payload):
    """
    Writes a cansend directive to a file.

    :param filename: The filename of the file to write to.
    :param arb_id: The arbitration id of the cansend directive.
    :param payload: The payload of the cansend directive.
    """
    fd = open(filename, "a")
    fd.write(arb_id + "#" + payload + "\n")
    fd.close()


# --- [1]
# Converter methods
# ---


def list_int_from_str_base(line):
    """
    Converts a given string to its list int representation.
    Uses CaringCaribou's int_from_str_base implementation.

    :param line: A given string that follows the format of (for example): "0xFF 0xFF 0xFF 0xFF".
    :return: Returns a list of ints representing the values in the string.
             For example: [0xFF, 0xFF, 0xFF, 0xFF] (with 0xFF in its int representation).
    """
    temp = line.split()
    for i in range(len(temp)):
        temp[i] = int_from_str_base(temp[i])
    return temp


def payload_to_str_base(payload):
    """
    Converts a given payload to its str_base representation.
    A str_base payload is for example: "0xFF 0xFF 0xFF 0xFF".

    :param payload: The payload to be converted.
    :return: Returns the str_base representation of the payload.
    """
    result = ""
    for i in range(0, len(payload), 2):
        result += "0x" + payload[i] + payload[i + 1] + " "
    result = result[:len(result) - 1]
    return result


def string_to_bool(value):
    """
    Converts a given string to a boolean.

    :param value:
    :return: False if value.upper() == "FALSE" or value == "0" or value == "" else True
    """
    return False if value.upper() == "FALSE" or value == "0" or value == "" else True


def parse_directive(line):
    """
    Parses a given cansend directive.

    :param line: A given string that represent a cansend directive.
    :return: Returns a composite directive: [id, payload]
    """
    composite = list()
    pointer = line.find("#")
    composite.append(line[0: pointer])
    composite.append(line[pointer + 1: len(line) - 1])
    return composite


# --- [2]
# Methods that handle random fuzzing.
# ---


def get_random_id():
    """
    Gets a random arbitration id.

    :return: A random arbitration id.
    """
    arb_id = random.choice(LEAD_ID_CHARACTERS)
    for i in range(2):
        arb_id += random.choice(CHARACTERS)
    return arb_id


def get_random_payload(length=8):
    """
    Gets a random payload.

    :param: length: The length of the payload.
    :return: A random payload.
    """
    length = length * 2
    payload = ""
    for i in range(length):
        payload += random.choice(CHARACTERS)
    return payload


def random_fuzz(static_arb_id, static_payload, logging=0, filename=None, length=8):
    """
    A simple random id fuzzer algorithm.
    Send random or static CAN payloads to random or static arbitration ids.
    Uses CanActions to send/receive from the CAN bus.

    :param logging: How many cansend directives must be kept in memory at a time.
    :param static_arb_id: Override the static id with the given id.
    :param static_payload: Override the static payload with the given payload.
    :param filename: The file where the cansend directives should be written to.
    :param length: The length of the payload, this is used if random payloads are used.
    """
    # Define a callback function which will handle incoming messages
    def response_handler(msg):
        print("Directive: " + arb_id + "#" + payload + " Received Message:" + str(msg))

    log = [None] * logging
    counter = 0
    while True:
        arb_id = (static_arb_id if static_arb_id is not None else get_random_id())
        payload = (static_payload if static_payload is not None else get_random_payload(length))

        directive_send(arb_id, payload, response_handler)

        counter += 1
        if logging != 0:
            log[counter % logging] = arb_id + "#" + payload

        if filename is not None:
            write_directive_to_file(filename, arb_id, payload)


# --- [3]
# Methods that handle linear fuzzing.
# ---


def gen_random_fuzz_file(filename, static_arb_id, static_payload, amount=100, length=8):
    """
    Generates a file containing random cansend directives.

    :param filename: The file where the cansend directives should be written to.
    :param static_arb_id: Override the static id with the given id.
    :param static_payload: Override the static payload with the given payload.
    :param amount: The amount of cansend directives to be generated.
    :param length: The length of the payload, this is used if random payloads are used.
    """
    fd = open(filename, 'w')
    for i in range(amount):
        arb_id = (static_arb_id if static_arb_id is not None else get_random_id())
        payload = (static_payload if static_payload is not None else get_random_payload(length))
        fd.write(arb_id + "#" + payload + "\n")
    fd.close()


def linear_file_fuzz(filename, logging=0):
    """
    Use a given input file to send can packets.
    Uses CanActions to send/receive from the CAN bus.

    :param filename: The file where the cansend directives should be read from.
    :param logging: How many cansend directives must be kept in memory at a time.
    :return:
    """
    # Define a callback function which will handle incoming messages
    def response_handler(msg):
        print("Directive: " + directive + " Received Message:" + str(msg))

    fd = open(filename, 'r')
    log = [None] * logging
    counter = 0
    for directive in fd:
        composite = parse_directive(directive)
        arb_id = composite[0]
        payload = composite[1]

        directive_send(arb_id, payload, response_handler)

        counter += 1
        if logging != 0:
            log[counter % logging] = directive


# --- [4]
# Methods that handle brute force fuzzing.
# ---


def reverse_payload(payload):
    """
    Reverses a given payload

    :param payload: The payload to be reversed.
    :return: The reverse of the given payload
    """
    result = ""
    for i in range(len(payload) - 1, -1, -1):
        result += payload[i]
    return result


def get_next_bf_payload(last_payload):
    """
    Gets the next brute force payload.
    This method uses a ring method to get the next payload.
    For example: 0001 -> 0002 and 000F -> 0010

    :param last_payload: The last payload that was used.
    :return: Returns the next brute force payload to be used.
    """
    # Find the most inner ring.
    ring = len(last_payload) - 1
    while last_payload[ring] == "F":
        ring -= 1

    if ring < 0:
        return last_payload

    # Get the position of the character at the position ring in the last payload in CHARACTERS.
    i = CHARACTERS.find(last_payload[ring])
    # Construct the next payload.
    # First keep all the unchanged characters, then add the incremented character,
    # set all the remaining characters to 0.
    payload = last_payload[:ring] + CHARACTERS[(i + 1) % len(CHARACTERS)] + "0" * (len(last_payload) - 1 - ring)

    return payload


def ring_bf_fuzz(arb_id, initial_payload=ZERO_PAYLOAD, logging=0, filename=None, length=8):
    """
    A simple brute force fuzzer algorithm.
    Attempts to brute force a static id using a ring based brute force algorithm.
    Uses CanActions to send/receive from the CAN bus.

    :param arb_id: The arbitration id to use.
    :param logging: How many cansend directives must be kept in memory at a time.
    :param initial_payload: The initial payload from where to start brute forcing.
    :param filename: The file where the cansend directives should be written to.
    :param length: The length of the payload, this is used if random payloads are used.
    """
    # Define a callback function which will handle incoming messages
    def response_handler(msg):
        print("Directive: " + arb_id + "#" + send_msg + " Received Message:" + str(msg))

    # Set payload to the part of initial_payload that will be used internally.
    payload = reverse_payload(initial_payload[:(length * 2) + 1])
    log = [None] * logging
    counter = 0

    # manually send first payload
    send_msg = reverse_payload(payload)
    directive_send(arb_id, send_msg, response_handler)

    counter += 1
    if logging != 0:
        log[counter % logging] = arb_id + "#" + payload

    while payload != "F" * 16:
        payload = get_next_bf_payload(payload)
        send_msg = reverse_payload(payload)

        directive_send(arb_id, send_msg, response_handler)

        counter += 1
        if logging != 0:
            log[counter % logging] = arb_id + "#" + payload

        if filename is not None:
            write_directive_to_file(filename, arb_id, payload)


# --- [5]
# Methods that handle mutation fuzzing.
# ---


def get_mutated_id(arb_id_bitmap, arb_id):
    """
    Gets a mutated arbitration id.

    :param arb_id_bitmap: Specifies what (hex) bits need to be mutated in the arbitration id.
    :param arb_id: The original arbitration id.
    :return: Returns a mutated arbitration id.
    """
    old_arb_id = arb_id
    new_arb_id = ""

    for i in range(len(arb_id_bitmap)):
        if arb_id_bitmap[i] and i == 0:
            new_arb_id += random.choice(LEAD_ID_CHARACTERS)
        elif i >= len(arb_id) or arb_id_bitmap[i]:
            new_arb_id += random.choice(CHARACTERS)
        else:
            new_arb_id += old_arb_id[i]

    return new_arb_id


def get_mutated_payload(payload_bitmap, payload):
    """
    Gets a mutated payload.

    :param payload_bitmap: Specifies what (hex) bits need to be mutated in the payload.
    :param payload: The original payload.
    :return: Returns a mutated payload.
    """
    new_payload = ""
    for i in range(len(payload_bitmap)):
        if i >= len(payload) or payload_bitmap[i]:
            new_payload += random.choice(CHARACTERS)
        else:
            new_payload += payload[i]
    return new_payload


def mutate_fuzz(initial_arb_id, initial_payload,
                arb_id_bitmap=test_arb_id_bitmap, payload_bitmap=test_payload_bitmap,
                logging=1, filename=None):
    """
    A simple mutation based fuzzer algorithm.
    Mutates (hex) bits in the given id/payload.
    The mutation bits are specified in the id/payload bitmaps.
    The mutations are random values.
    Uses CanActions to send/receive from the CAN bus.

    :param initial_arb_id: The initial arbitration id to use.
    :param initial_payload: The initial payload to use.
    :param arb_id_bitmap: Specifies what (hex) bits need to be mutated in the arbitration id.
    :param payload_bitmap: Specifies what (hex) bits need to be mutated in the payload.
    :param logging: How many cansend directives must be kept in memory at a time.
    :param filename: The file where the cansend directives should be written to.
    """
    # Define a callback function which will handle incoming messages
    def response_handler(msg):
        print("Directive: " + arb_id + "#" + payload + " Received Message:" + str(msg))

    # payload_bitmap = [False, False, True, True, False, False, False, False]
    log = [None] * logging
    counter = 0
    while True:
        arb_id = get_mutated_id(arb_id_bitmap, initial_arb_id)
        payload = get_mutated_payload(payload_bitmap, initial_payload)

        directive_send(arb_id, payload, response_handler)

        counter += 1
        if logging != 0:
            log[counter % logging] = arb_id + "#" + payload

        if filename is not None:
            write_directive_to_file(filename, arb_id, payload)


# --- [6]
# Handler methods.
# ---


def handle_random(args):
    if args.payload is None and args.static_payload:
        raise ValueError

    random_fuzz(static_arb_id=args.id,
                static_payload=args.payload,
                logging=args.log,
                filename=args.file)


def handle_linear(args):
    filename = args.file
    if filename is None:
        raise NameError

    if args.gen:
        gen_random_fuzz_file(filename, static_payload=args.payload, static_arb_id=args.id)

    linear_file_fuzz(filename=filename, logging=args.log)


def handle_ring_bf(args):
    payload = args.payload
    if payload is None:
        payload = ZERO_PAYLOAD

    if args.id is None:
        raise ValueError

    ring_bf_fuzz(arb_id=args.id, initial_payload=payload, logging=args.log, filename=args.file)


def handle_mutate(args):
    payload = args.payload
    if payload is None:
        payload = ZERO_PAYLOAD

    arb_id = args.id
    if args.id is None:
        arb_id = ZERO_PAYLOAD

    mutate_fuzz(initial_payload=payload, initial_arb_id=arb_id, logging=args.log)


def handle_args(args):
    """
    Set up the environment using the passed arguments and execute the correct algorithm.

    :param args: Module argument list passed by cc.py
    """
    args.static = string_to_bool(str(args.static))
    args.gen = string_to_bool(str(args.gen))
    args.static_id = string_to_bool(str(args.static_id))
    args.static_payload = string_to_bool(str(args.static_payload))

    if args.id and len(args.id) > 3:
        raise ValueError

    if args.payload and (len(args.payload) % 2 != 0 or len(args.payload) > 16):
        raise ValueError

    if args.alg == "random":
        handle_random(args)
    elif args.alg == "linear":
        handle_linear(args)
    elif args.alg == "ring_bf":
        handle_ring_bf(args)
        return
    elif args.alg == "mutate":
        handle_mutate(args)
    else:
        raise ValueError


# --- [7]
# Main methods.
# ---


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

                                            + """\nCurrently supported algorithms:
                                     random - Send random or static CAN payloads to 
                                              random or static arbitration ids.
                                     linear - Use a given input file to send can packets.
                                     ring_bf - Attempts to brute force a static id 
                                               using a ring based brute force algorithm.
                                     mutate - Mutates (hex) bits in the given id/payload.
                                              The mutation bits are specified in the id/payload bitmaps.""")

    parser.add_argument("-static", type=str, default="True", help="Do not use static payloads (default is True)")

    # boolean values are initially stored as strings, call to_bool() before use!
    parser.add_argument("-alg", type=str, help="What fuzzing algorithm to use.")
    parser.add_argument("-log", type=int, default=0,
                        help="How many cansend directives must be kept in memory at a time (default is 0)")

    parser.add_argument("-file", type=str, help="Specify a file to where the fuzzer should write"
                                                "the cansend directives it uses. "
                                                "This is required for the linear algorithm.")
    parser.add_argument("-gen", type=str, default="False",
                        help="Generate a cansend directive file to the file specified with -file. "
                             "Only used by the linear algorithm to generate "
                             "an initial file containing random directives.")

    parser.add_argument("-static_id", type=str, default="False", help="Do not use static ids (default is False)")
    parser.add_argument("-id", type=str, help="Override the default id with a different id."
                                              " Use the following syntax: 123")
    parser.add_argument("-id_bitmap", type=str, help="Override the default id bitmap with a different id bitmap. "
                                                     "Use the following syntax: [True, False, True]")

    parser.add_argument("-static_payload", type=str, default="False",
                        help="Do not use static payloads (default is FALSE)")
    parser.add_argument("-payload", type=str, help="Override the default payload with a different payload. "
                                                   "Use the following syntax: FFFFFFFF")
    parser.add_argument("-payload_bitmap", type=str,
                        help="Override the default payload bitmap with a different payload bitmap. "
                             "Use the following syntax: [True, False, True, False, ...]")

    args = parser.parse_args(args)
    return args


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
