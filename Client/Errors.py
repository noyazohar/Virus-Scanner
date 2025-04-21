class ErrorBase(Exception):
    """
    Base class for all custom exceptions.

    Attributes:
        message (str): Description of the error.
    """
    def __init__(self, message="An unknown error has occurred"):
        """
        Initialize the base error with a default or custom message.

        Args:
            message (str): The error message to be stored.
        """
        self.message = message
        super().__init__(self.message)

class ConnectionError(ErrorBase):
    """
    Exception raised for server connection errors.

    Attributes:
        message (str): Description of the connection error.
    """
    def __init__(self, message="Failed to connect to the server"):
        """
        Initialize the connection error with a default or custom message.

        Args:
            message (str): The error message to be stored.
        """
        super().__init__(message)

class ServerError(ErrorBase):
    """
    Exception raised for server-side errors.

    Attributes:
        message (str): Description of the server error.
    """
    def __init__(self, message="A server-side error occurred"):
        """
        Initialize the server error with a default or custom message.

        Args:
            message (str): The error message to be stored.
        """
        super().__init__(message)

class ClientError(ErrorBase):
    """
    Exception raised for client-side errors.

    Attributes:
        message (str): Description of the client error.
    """
    def __init__(self, message="A client-side error occurred"):
        """
        Initialize the client error with a default or custom message.

        Args:
            message (str): The error message to be stored.
        """
        super().__init__(message)
