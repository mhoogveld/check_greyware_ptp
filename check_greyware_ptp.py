#!/usr/bin/python
# -*- coding: utf-8 -*-

"""

"""

from __future__ import division, print_function, absolute_import
import argparse
import datetime
from decimal import *
import re
import sys
import os.path
import ctypes

__author__ = 'Maarten Hoogveld'
__version__ = '0.1.1'
__email__ = 'maarten@hoogveld.org'
__licence__ = 'GPL-3.0'
__status__ = 'Production'


class GreywarePtpChecker:
    STATUS_OK = 0
    STATUS_WARNING = 1
    STATUS_CRITICAL = 2
    STATUS_UNKNOWN = 3

    # Verbosity levels
    V_NONE = 0
    V_INFO = 1
    V_DEBUG = 2

    # Max measurement age in minutes (the date of the last entry in the log file)
    MAX_MEASUREMENT_AGE = 4

    def __init__(self):
        self.status = None
        self.messages = []
        self.perfdata = []
        self.delta_time_unit = 'µs'
        self.options = None

    def run(self):
        self.parse_options()
        self.check()
        self.print_output()
        return

    def check(self):
        """
        Perform time delta check based on entries in the logfile
        :return:
        """
        self.print_msg(self.V_DEBUG, 'Performing time delta check based on entries in the logfile')

        # Initialize result status as OK
        self.add_status(self.STATUS_OK)

        if sys.platform == 'win32':
            disable_file_system_redirection().__enter__()

        if not os.path.exists(self.options.logfile):
            self.add_status(self.STATUS_UNKNOWN)
            self.add_message('Can\'t read logfile')
            return

        summary_line = self.get_last_summary_line(self.options.logfile)
        if summary_line is None:
            self.add_status(self.STATUS_UNKNOWN)
            self.add_message('Can\'t read delta from logfile')
            return

        last_delta_usec = self.parse_line_for_delta_usec(summary_line)
        last_measurement_datetime = self.parse_line_for_datetime(summary_line)
        min_last_measurement_datetime = datetime.datetime.now() - datetime.timedelta(minutes=self.MAX_MEASUREMENT_AGE)

        if last_measurement_datetime < min_last_measurement_datetime:
            self.add_status(self.STATUS_UNKNOWN)
            self.add_message(
                'PTP drift data considered stale. Last log data is from {}.'.format(
                    last_measurement_datetime.strftime('%c')
                )
            )
        elif last_delta_usec is None:
            self.add_status(self.STATUS_UNKNOWN)
            self.add_message('PTP drift delta can not be read from log file')
        elif self.options.critical is not None and last_delta_usec >= self.options.critical:
            self.add_status(self.STATUS_CRITICAL)
            self.add_message(
                'PTP drift delta is {delta}{unit} which is over critical threshold of {crit}{unit}'.format(
                    delta=round(last_delta_usec),
                    crit=self.options.critical,
                    unit=self.delta_time_unit
                )
            )
        elif self.options.warning is not None and last_delta_usec >= self.options.warning:
            self.add_status(self.STATUS_WARNING)
            self.add_message(
                'PTP drift delta is {delta}{unit} which is over warning threshold of {warn}{unit}'.format(
                    delta=round(last_delta_usec),
                    warn=self.options.warning,
                    unit=self.delta_time_unit
                )
            )

        if self.options.perf and last_delta_usec is not None:
            perfmsg = 'delta={delta}{unit}'.format(delta=round(last_delta_usec), unit=self.delta_time_unit)
            if self.options.warning is not None and self.options.critical is not None:
                perfmsg += ';{warn};{crit}'.format(warn=self.options.warning, crit=self.options.critical)
            self.add_perfdata(perfmsg)

    def parse_options(self):
        parser = argparse.ArgumentParser(
            description='Monitoring check plugin to check the PTP process by reading the contents of the '
                        'Greyware logfile'
        )
        parser.add_argument('--version', action='version', version='%(prog)s {version}'.format(version=__version__),
                            help='The version of this script')
        parser.add_argument('--logfile',
                            default='C:/Windows/System32/domtimec.log', help='The location of the logfile to read')
        parser.add_argument('--perf',
                            action='store_true', help='Return performance data (drift in microseconds)')
        parser.add_argument('--critical',
                            default=None, type=int, help='Critical threshold in amount of drift in microseconds')
        parser.add_argument('--warning',
                            default=None, type=int, help='Warning threshold in amount of drift in microseconds')
        parser.add_argument('--ascii-only',
                            action='store_true', help='Output only ASCII characters. (Don\'t use the "mu" character)')
        parser.add_argument('--no-utf8',
                            default=0, help='Verbose output')
        parser.add_argument('--verbose',
                            default=0, type=int, choices=[0, 1, 2], help='Verbose output')
        self.options = parser.parse_args()

        if not self.are_options_valid():
            print('Run with --help for usage information')
            print('')
            exit(0)

        if self.options.ascii_only:
            self.delta_time_unit = 'us'

        self.print_msg(self.V_DEBUG, 'Using parameters:')
        self.print_msg(self.V_DEBUG, ' Logfile:             {}'.format(self.options.logfile))
        self.print_msg(self.V_DEBUG, ' Warning threshold:   {}'.format(
            str(self.options.warning) + self.delta_time_unit if self.options.warning else ''))
        self.print_msg(self.V_DEBUG, ' Critical threshold:  {}'.format(
            str(self.options.critical) + self.delta_time_unit if self.options.critical else ''))
        self.print_msg(self.V_DEBUG, ' Verbosity:           {}'.format(self.options.verbose))
        self.print_msg(self.V_DEBUG, '')

    def are_options_valid(self):
        if self.options.critical and self.options.warning:
            if self.options.critical < self.options.warning:
                print('The critical threshold must be higher or equal to the warning threshold')
                return False
        return True

    def print_msg(self, minimum_verbosity_level, msg):
        """
        :param minimum_verbosity_level: Minimum verbosity level needed for the message to be printed
        :param msg: The message to print
        :return:
        """
        if self.options.verbose >= minimum_verbosity_level:
            print(msg)

    def print_output(self):
        """ Prints the final output (in Nagios plugin format if self.status is set)
        :return:
        """
        self.print_msg(self.V_DEBUG, 'Printing final output')
        output = ''
        if self.status == self.STATUS_OK:
            output = 'OK'
        elif self.status == self.STATUS_WARNING:
            output = 'Warning'
        elif self.status == self.STATUS_CRITICAL:
            output = 'Critical'
        elif self.status == self.STATUS_UNKNOWN:
            output = 'Unknown'

        if self.messages:
            if len(output):
                output += ' - '
            # Join messages like sentences. Correct those messages which already ended with a period or a newline.
            output += '. '.join(self.messages).replace('.. ', '.').replace('\n. ', '\n')

        if self.perfdata:
            if len(output):
                output += ' | '
            output += ' '.join(self.perfdata)

        print(output)

    def add_status(self, status):
        """ Set the status only if it is more severe than the present status
        The order of severity being OK, WARNING, CRITICAL, UNKNOWN
        :param status: Status to set, one of the self.STATUS_xxx constants
        :return: The current status
        """
        if self.status is None or status > self.status:
            self.status = status

    def set_message(self, message):
        self.messages = [message]

    def add_message(self, message, prepend=False):
        if prepend:
            self.messages.insert(0, message)
        else:
            self.messages.append(message)

    def add_perfdata(self, perfitem, prepend=False):
        if prepend:
            self.perfdata.insert(0, perfitem)
        else:
            self.perfdata.append(perfitem)

    @staticmethod
    def get_last_summary_line(logfile):
        last_lines = FileTail.tail(logfile, 20)
        for line in reversed(last_lines.splitlines()):
            if GreywarePtpChecker.is_summary_line(line):
                return line
        return None

    @staticmethod
    def is_summary_line(line):
        return re.search(r'Summary: .* delta is', line) is not None

    @staticmethod
    def parse_line_for_delta_usec(line):
        summary_reg_exp = r'Summary: .* delta is ([\+\-0-9\.]+) seconds'
        match = re.search(summary_reg_exp, line)
        if match is None:
            return None
        else:
            delta = match.group(1)
            # Remove the '+' prefix if present
            if delta.startswith('+'):
                delta = delta[1:]

            delta_microseconds = Decimal(delta) * 1000000
            return delta_microseconds

    @staticmethod
    def parse_line_for_datetime(line):
        datetime_re = '[A-z]{3} [A-z]{3} [0-9]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}'
        match = re.search(datetime_re, line)
        if match is None:
            return None
        else:
            return datetime.datetime.strptime(match.group(0), '%a %b %d %Y %H:%M:%S')


class FileTail:
    @staticmethod
    def tail(filename, lines=20):
        newline_char = FileTail.detect_newline_char(filename)
        f = open(filename, 'rb')

        total_lines_wanted = lines

        block_size = 1024
        f.seek(0, 2)
        block_end_byte = f.tell()
        lines_to_go = total_lines_wanted
        block_number = -1

        # blocks of size block_size, in reverse order starting
        blocks = []

        # From the end of the file
        while lines_to_go > 0 and block_end_byte > 0:
            if block_end_byte - block_size > 0:
                # Read the last block we haven't yet read
                f.seek(block_number * block_size, 2)
                blocks.append(f.read(block_size))
            else:
                # File too small, start from beginning
                f.seek(0, 0)
                # Only read what was not read
                blocks.append(f.read(block_end_byte))

            lines_found = blocks[-1].count(newline_char.encode('utf-8'))
            lines_to_go -= lines_found
            block_end_byte -= block_size
            block_number -= 1

        f.close()
        all_read_text = b''.join(reversed(blocks)).decode('utf-8')
        return newline_char.join(all_read_text.splitlines()[-total_lines_wanted:])

    @staticmethod
    def detect_newline_char(filename):
        f = open(filename, 'rb')
        first_line = f.readline()
        f.close()
        if first_line[-2:] == b'\r\n':
            return '\r\n'
        elif first_line[-1:] == b'\n':
            return '\n'
        elif first_line[-1:] == b'\r':
            return '\r'
        else:
            return ''


class disable_file_system_redirection:
    """
    Class to disable and enable Windows file system redirection
    For example, when enabled, files in C:/Windows/system32/ are not readable in python
    """
    if sys.platform == 'win32':
        _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
        _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection

    def __enter__(self):
        if sys.platform == 'win32':
            self.old_value = ctypes.c_long()
            self.success = self._disable(ctypes.byref(self.old_value))

    def __exit__(self, type, value, traceback):
        if sys.platform == 'win32':
            if self.success:
                self._revert(self.old_value)


if __name__ == '__main__':
    checker = GreywarePtpChecker()
    checker.run()
    exit(checker.status)
