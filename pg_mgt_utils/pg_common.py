# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c) 2014, Toshio Kuratomi <tkuratomi@ansible.com>
#
# Simplified BSD License (see simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

"""
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, 
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, 
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""


"""
Common functions for database modules.
Adapted from the Ansible PostgreSQL module - https://github.com/ansible-collections/community.postgresql/blob/main/plugins/module_utils/database.py
"""


import re
import logging
import os


log_level = os.environ.get('LOG_LEVEL', 'INFO')
logging.basicConfig(level=log_level)

logger = logging.getLogger(__name__)


# Input patterns for is_input_dangerous function:
#
# 1. '"' in string and '--' in string or
# "'" in string and '--' in string
PATTERN_1 = re.compile(r'(\'|\").*--')

# 2. union \ intersect \ except + select
PATTERN_2 = re.compile(r'(UNION|INTERSECT|EXCEPT).*SELECT', re.IGNORECASE)

# 3. ';' and any KEY_WORDS
PATTERN_3 = re.compile(r';.*(SELECT|UPDATE|INSERT|DELETE|DROP|TRUNCATE|ALTER)', re.IGNORECASE)


class SQLParseError(Exception):
    pass


class UnclosedQuoteError(SQLParseError):
    pass


# maps a type of identifier to the maximum number of dot levels that are
# allowed to specify that identifier.  For example, a database column can be
# specified by up to 4 levels: database.schema.table.column
_PG_IDENTIFIER_TO_DOT_LEVEL = dict(
    database=1,
    schema=2,
    table=3,
    column=4,
    role=1,
    tablespace=1,
    sequence=3,
    publication=1,
)

def _find_end_quote(identifier, quote_char):
    accumulate = 0
    while True:
        try:
            quote = identifier.index(quote_char)
        except ValueError:
            raise UnclosedQuoteError
        accumulate = accumulate + quote
        try:
            next_char = identifier[quote + 1]
        except IndexError:
            return accumulate
        if next_char == quote_char:
            try:
                identifier = identifier[quote + 2:]
                accumulate = accumulate + 2
            except IndexError:
                raise UnclosedQuoteError
        else:
            return accumulate


def _identifier_parse(identifier, quote_char):
    if not identifier:
        raise SQLParseError('Identifier name unspecified or unquoted trailing dot')

    already_quoted = False
    if identifier.startswith(quote_char):
        already_quoted = True
        try:
            end_quote = _find_end_quote(identifier[1:], quote_char=quote_char) + 1
        except UnclosedQuoteError:
            already_quoted = False
        else:
            if end_quote < len(identifier) - 1:
                if identifier[end_quote + 1] == '.':
                    dot = end_quote + 1
                    first_identifier = identifier[:dot]
                    next_identifier = identifier[dot + 1:]
                    further_identifiers = _identifier_parse(next_identifier, quote_char)
                    further_identifiers.insert(0, first_identifier)
                else:
                    raise SQLParseError('User escaped identifiers must escape extra quotes')
            else:
                further_identifiers = [identifier]

    if not already_quoted:
        try:
            dot = identifier.index('.')
        except ValueError:
            identifier = identifier.replace(quote_char, quote_char * 2)
            identifier = ''.join((quote_char, identifier, quote_char))
            further_identifiers = [identifier]
        else:
            if dot == 0 or dot >= len(identifier) - 1:
                identifier = identifier.replace(quote_char, quote_char * 2)
                identifier = ''.join((quote_char, identifier, quote_char))
                further_identifiers = [identifier]
            else:
                first_identifier = identifier[:dot]
                next_identifier = identifier[dot + 1:]
                further_identifiers = _identifier_parse(next_identifier, quote_char)
                first_identifier = first_identifier.replace(quote_char, quote_char * 2)
                first_identifier = ''.join((quote_char, first_identifier, quote_char))
                further_identifiers.insert(0, first_identifier)

    return further_identifiers


def pg_quote_identifier(identifier, id_type):
    check_input(identifier)
    identifier_fragments = _identifier_parse(identifier, quote_char='"')
    if len(identifier_fragments) > _PG_IDENTIFIER_TO_DOT_LEVEL[id_type]:
        raise SQLParseError('PostgreSQL does not support %s with more than %i dots' % (id_type, _PG_IDENTIFIER_TO_DOT_LEVEL[id_type]))
    return '.'.join(identifier_fragments)



def is_input_dangerous(string):
    """Check if the passed string is potentially dangerous.
    Can be used to prevent SQL injections.

    Note: use this function only when you can't use
      psycopg2's cursor.execute method parametrized
      (typically with DDL queries).
    """
    if not string:
        return False

    for pattern in (PATTERN_1, PATTERN_2, PATTERN_3):
        if re.search(pattern, string):
            return True

    return False


def check_input(*args):
    """Wrapper for is_input_dangerous function."""
    needs_to_check = args

    dangerous_elements = []

    for elem in needs_to_check:
        try:
            if isinstance(elem, str):
                if is_input_dangerous(elem):
                    dangerous_elements.append(elem)

            elif isinstance(elem, list):
                for e in elem:
                    if is_input_dangerous(e):
                        dangerous_elements.append(e)

            elif elem is None or isinstance(elem, bool):
                pass

            else:
                elem = str(elem)
                if is_input_dangerous(elem):
                    dangerous_elements.append(elem)
        except ValueError as e:
            logger.error("Error while checking input: %s", str(e))
            raise ValueError(e)

    if dangerous_elements:
        error_msg = "Passed input '%s' is potentially dangerous" % ', '.join(dangerous_elements)
        logger.error(error_msg)
        raise ValueError(error_msg)