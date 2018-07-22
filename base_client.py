"""
.. note::
    **Do not change any code in this file!** Your client implementation should
    be written in `client.py`---this file contains the base class your Client
    class will be based off of.
"""


class IntegrityError(RuntimeError):
    """Error to raise whenever an integrity error is encountered."""
    pass


class BaseClient(object):
    """Base class to build a file store client off of.

    You should build your secure client implementation in ``client.py``,
    subclassing off of this base class.
    """
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        """Initializes a new BaseClient object.

        This sets the username, storage server, public key server, crypto
        object, and private key for the client.

        Your Client subclass should call `super().__init__()` to call this
        initializer, or copy this code as needed.

        :param StorageServer storage_server: A StorageServer object.
        :param PublicKeyServer public_key_server: A PublicKeyServer object.
        :param Crypto crypto_object: A Crypto object (see crypto.py and
            InsecureClient for how this is used)
        :param str username: The username for this client. You may assume that
            usernames consist solely of lower-case letters (``[a-z]+``).
        """
        self.username = username
        self.storage_server = storage_server
        self.pks = public_key_server
        self.crypto = crypto_object
        self.private_key = self.generate_public_key_pair()

    def generate_public_key_pair(self):
        """Create a public key pair for this client.

        .. note::
            You should call this exactly once in the initialization of your
            client, passing the size of the key desired. This method will
            automatically put the key to the public key server, and save a copy
            of your private key to the filesystem. This is the only persistent
            state that your client can use (that is, you can assume that for
            the same username, a client will have the same public/private keys
            even if restarted).

        If the key already exists, this will load it from the filesystem.

        If the key does not exist, this will create a new key pair, upload the
        public key to the Public Key Server, and save a copy of the private key
        to the filesystem (as ``keys/<username>.pem``).

        This creates RSA keys with 2048-bit modulus. It returns an RSA key
        object which contains both the public and private key. You can pass
        this object to functions that take a public or private key.

        :returns: An RSA key object containing both the public and private key.
            For more details see the PyCrypto documentation for `_RSAobj
            <https://pythonhosted.org/pycrypto/Crypto.PublicKey.RSA._RSAobj-class.html>`_.
        """
        private_key = self.crypto._load_keyfile(self.username)
        if private_key:
            public_key = private_key.publickey()
        else:
            public_key, private_key = self.crypto._gen_asymmetric_keypair(2048)
            self.crypto._save_keyfile(self.username, private_key)
        self.pks.put_public_key(self.username, public_key)
        return private_key

    def upload(self, name, value):
        """Places the string `value` at `name` so that future calls to
        ``download`` for `name` return `value`.

        A secure client implementation of this method should meet all of the
        required properties listed in the project specification.

        :param str name: The name of the file. You can assume file names are
            alphanumeric (that is, they match the regex ``[A-Za-z0-9]+``).
        :param str value: The value to upload.
        """
        raise NotImplementedError

    def download(self, name):
        """Returns the last value stored at `name` by the owner or anyone with
        whom it has been shared, or `None` if the file does not exist.

        A secure client implementation of this method should meet all of the
        required properties listed in the project specification.

        :param str name: The name of the file. You can assume file names are
            alphanumeric (that is, they match the regex ``[A-Za-z0-9]+``).
        :returns: A string, the last value stored at `name`, or None if the
            file does not exist.
        """
        raise NotImplementedError

    def share(self, user, name):
        """Share a file `name` with `user`.

        A secure client implementation of this method should meet all of the
        required properties listed in the project specification.

        ``share`` and ``receive_share`` work together as follows:

        ::

           msg = alice.share("bob", filename)
           bob.receive_share("alice", msg, newfilename)

        :param str user: The username of the user you are sharing with.
        :param str name: The name of the file you are sharing with `user`.
        :returns: A string, containing the message to give to `user` through an
            out-of-band channel that will let them access the file.
        """
        raise NotImplementedError

    def receive_share(self, from_username, message, newname):
        """Receive a share message generated by the `share` method of another
        client with username `from_username`.
        Once this is done, the client calling this method should now be able to
        access the shared file under the name `newname`.

        A secure client implementation of this method should meet all of the
        required properties listed in the project specification.

        ``share`` and ``receive_share`` work together as follows:

        ::

           msg = alice.share("bob", filename)
           bob.receive_share("alice", msg, newfilename)

        :param str from_username: The username of the sharing client.
        :param str message: The message generated by the sharing client's
            `share` method.
        :param str newname: The new filename under which this client will
            access the file.
        """
        raise NotImplementedError

    def revoke(self, user, name):
        """Revokes `user`'s access to the file `name`.

        `user` should not be able to observe new updated to `name`, and should
        not be able update it.

        Anyone with whom `user` shared this file should also be revoked.

        You may not send any messages during revocation.

        A secure client implementation of this method should meet all of the
        required properties listed in the project specification.

        :param str user: The username of the user whose access will be revoked
        :param str name: The name of the file
        """
        raise NotImplementedError
