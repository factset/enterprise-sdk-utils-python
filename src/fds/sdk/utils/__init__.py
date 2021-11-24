import logging
from logging import NullHandler

# Set default logging handler to avoid "No handler found" warnings.
# See: https://docs.python.org/3/howto/logging.html#library-config
logging.getLogger(__name__).addHandler(NullHandler())
del NullHandler
