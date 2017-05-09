"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""
from base_client import BaseClient, IntegrityError
from crypto import CryptoError
seg_size = 12000
seg_buffer = 11999.9999

class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)

    def upload(self, name, value):
        hex_digits = set("0123456789abcdef")
        #generates unique name for the file to be stored under in the server
        stored_name = self.crypto.cryptographic_hash(self.private_key.exportKey().decode("utf-8", 'ignore') + name, 'SHA256')
        new_key = self.crypto.get_random_bytes(16)
        #Every user with access to the file will have the secret key encrypted using their public keys stored in keys_names along with the user's name
        #generates a new key, checks if the file already exists and if there already is a key in keys_names
        keys = self.storage_server.get(stored_name + "_keys_names")
        if not keys == None:
            keys = keys.split(',')
            new_key = None
            last_key = None
            for key in keys:
                if last_key == self.username:
                    if not all(c in hex_digits for c in key):
                        raise IntegrityError
                    try: 
                        new_key = str(self.crypto.asymmetric_decrypt(key, self.private_key))
                    except (UnicodeDecodeError, CryptoError):
                        raise IntegrityError
                last_key = key
            if new_key == None or not all(c in hex_digits for c in new_key):
                raise IntegrityError
        share_info = self.storage_server.get(stored_name + "_share_info")
        #share_info stores a tree structure that shows who shared the file to what user
        stored_names = []
        if share_info == None:
            self.storage_server.put(stored_name + "_share_info", str(self.crypto.symmetric_encrypt(self.username + ".creator." + stored_name, new_key, 'AES')))
            stored_names = [stored_name]
            self.storage_server.put(stored_name + "_keys_names", self.username + "," + str(self.crypto.asymmetric_encrypt(new_key, self.pks.get_public_key(self.username))))
        else:
            if not all(c in hex_digits for c in share_info):
                raise IntegrityError
            try: 
                share_info = self.crypto.symmetric_decrypt(share_info, new_key, 'AES')
            except (UnicodeDecodeError, CryptoError):
                    raise IntegrityError
            shared_users = share_info.split(',')
            for user in shared_users:
                user_info = user.split('.')
                user_stored_name = user_info[2]
                stored_names.append(user_stored_name)
        #edit_info stores the size in number of segments of the encrypted file
        old_edit_info = self.storage_server.get(stored_name + "_edit_info")
        edit_info = str(self.crypto.symmetric_encrypt(str(int((len(value) + seg_buffer)/seg_size)), new_key, 'AES'))
        same_size = old_edit_info == edit_info
        #tag stoes a hash of the secret key and the file to to maintain integrity
        tag = str(self.crypto.cryptographic_hash(new_key + value,'SHA256'))
        for name in stored_names:
            if not same_size:
                self.storage_server.put(name + "_edit_info", edit_info)
            self.storage_server.put(name +"_tag",tag)
        number_segments = int((len(value) + seg_buffer)/seg_size)
        #splits the file into segments and encrypts each one individually along with a hash for efficient updating
        for n in range(1, number_segments + 1):
            segment_tag = str(self.crypto.cryptographic_hash(new_key + value[int(n-1)*seg_size:n*seg_size],'SHA256'))[:4]
            ciphertext = str(self.crypto.symmetric_encrypt(value[int(n-1)*seg_size:n*seg_size], new_key, 'AES'))
            for name in stored_names:
                if same_size:
                    if self.storage_server.get(name + str(n) + "tag") != segment_tag:

                        self.storage_server.put(name + str(n), ciphertext)
                        self.storage_server.put(name + str(n) + "tag", segment_tag)
                else:
                    self.storage_server.put(name + str(n), ciphertext)
                    self.storage_server.put(name + str(n) + "tag", segment_tag)
        return True

    def download(self, name):
        # Replace with your implementation
        #raise NotImplementedError
        hex_digits = set("0123456789abcdef")
        stored_name = self.crypto.cryptographic_hash(self.private_key.exportKey().decode("utf-8", 'ignore') + name, 'SHA256')
        keys = self.storage_server.get(stored_name + "_keys_names")
        if keys == None:
            return None
        keys = keys.split(',')
        new_key = None
        last_key = None
        for key in keys:
            if last_key == self.username:
                if not all(c in hex_digits for c in key):
                    raise IntegrityError
                try: 
                    new_key = str(self.crypto.asymmetric_decrypt(key, self.private_key))
                except (UnicodeDecodeError, CryptoError):
                    raise IntegrityError
            last_key = key
        if new_key == None or not all(c in hex_digits for c in new_key):
            raise IntegrityError

        edit_info = self.storage_server.get(stored_name + "_edit_info")
        if edit_info == None or not all(c in hex_digits for c in edit_info):
            raise IntegrityError
        share_info = self.storage_server.get(stored_name + "_share_info")
        #check if stored_name is the same as the stored_name in share_info
        correct_stored_name = 0
        if share_info == None:
            raise IntegrityError
        else:
            if not all(c in hex_digits for c in share_info):
                raise IntegrityError
            try: 
                share_info = self.crypto.symmetric_decrypt(share_info, new_key, 'AES')
            except (UnicodeDecodeError, CryptoError):
                    raise IntegrityError
            shared_users = share_info.split(',')
            for user in shared_users:
                user_info = user.split('.')
                if user_info[0] == self.username:
                    correct_stored_name = 1
                    if not stored_name == user_info[2]:
                        raise IntegrityError
        if correct_stored_name == 0:
            raise IntegrityError
        number_segments = 0
        try:
            number_segments = int(self.crypto.symmetric_decrypt(edit_info, new_key, 'AES'))
        except (UnicodeDecodeError, CryptoError):
            raise IntegrityError

        value = ""
        for n in range(1, number_segments + 1):
            ciphertext = self.storage_server.get(stored_name + str(n))
            if ciphertext == None or not all(c in hex_digits for c in ciphertext):
                raise IntegrityError
            try:
                value += self.crypto.symmetric_decrypt(ciphertext, new_key, 'AES')
            except (UnicodeDecodeError, CryptoError):
                raise IntegrityError
        tag = self.storage_server.get(stored_name +"_tag")
        new_tag = str(self.crypto.cryptographic_hash(new_key + value,'SHA256'))
        if tag != new_tag:
            raise IntegrityError
        else:
            return value

    def share(self, user, name):
        #shares the file with another user
        value = self.download(name)
        stored_name = self.crypto.cryptographic_hash(self.private_key.exportKey().decode("utf-8", 'ignore') + name, 'SHA256')
        share_info = self.storage_server.get(stored_name + "_share_info")
        if value == None or share_info == None:
            return None
        keys = self.storage_server.get(stored_name + "_keys_names").split(',')
        new_key = None
        last_key = None
        for key in keys:
            if last_key == self.username:
                new_key = str(self.crypto.asymmetric_decrypt(key, self.private_key))
            last_key = key
        user_key = self.pks.get_public_key(user)
        sent_key = str(self.crypto.asymmetric_encrypt(new_key, user_key))
        sent_value = str(self.crypto.symmetric_encrypt(value, new_key, 'AES'))
        sent_tag = str(self.crypto.cryptographic_hash(new_key + value,'SHA256'))
        keys_names = self.storage_server.get(stored_name + "_keys_names")
        return sent_key + "." + sent_value + "." + sent_tag + "." + share_info + "." + keys_names

    def receive_share(self, from_username, newname, message):
        if message == None:
            return None
        msg = message.split('.')
        if not len(msg) == 5:
            raise IntegrityError
        new_key = self.crypto.asymmetric_decrypt(msg[0], self.private_key)
        value = self.crypto.symmetric_decrypt(msg[1], new_key, 'AES')
        tag = msg[2]
        new_tag = str(self.crypto.cryptographic_hash(new_key + value,'SHA256'))
        if not tag == new_tag:
            raise IntegrityError
        share_info = self.crypto.symmetric_decrypt(msg[3], new_key, 'AES')
        if not from_username in share_info:
            raise IntegrityError
        stored_name = self.crypto.cryptographic_hash(self.private_key.exportKey().decode("utf-8", 'ignore') + newname, 'SHA256')
        share_info = share_info +  "," + self.username + "." + from_username + "." + stored_name
        keys_names = msg[4]
        if not from_username in keys_names:
            raise IntegrityError
        keys_names = keys_names +  "," + self.username + "," + str(self.crypto.asymmetric_encrypt(new_key, self.pks.get_public_key(self.username)))

        #updating share info for all shared users
        shared_users = share_info.split(',')
        for user in shared_users:
            user_info = user.split('.')
            user_stored_name = user_info[2]
            self.storage_server.put(user_stored_name + "_share_info", str(self.crypto.symmetric_encrypt(share_info, new_key, 'AES')))
            self.storage_server.put(user_stored_name + "_keys_names", keys_names)

        #uploading file you just got
        self.storage_server.put(stored_name + "_edit_info", str(self.crypto.symmetric_encrypt(str(int((len(value) + seg_buffer)/seg_size)), new_key, 'AES')))
        self.storage_server.put(stored_name +"_tag",tag)
        number_segments = int((len(value) + seg_buffer)/seg_size)
        for n in range(1, number_segments + 1):
            self.storage_server.put(stored_name + str(n), str(self.crypto.symmetric_encrypt(value[int(n-1)*seg_size:n*seg_size], new_key, 'AES')))
            self.storage_server.put(stored_name + str(n) + "tag", str(self.crypto.cryptographic_hash(new_key + value[int(n-1)*seg_size:n*seg_size],'SHA256'))[:4])

        

    def revoke(self, user, name):
        #revoke access to file for specified user and whoever they shared it to
        value = self.download(name)
        hex_digits = set("0123456789abcdef")
        stored_name = self.crypto.cryptographic_hash(self.private_key.exportKey().decode("utf-8", 'ignore') + name, 'SHA256')
        keys = self.storage_server.get(stored_name + "_keys_names")
        if keys == None:
            return None
        keys = keys.split(',')
        new_key = None
        last_key = None
        for key in keys:
            if last_key == self.username:
                if not all(c in hex_digits for c in key):
                    raise IntegrityError
                try: 
                    new_key = str(self.crypto.asymmetric_decrypt(key, self.private_key))
                except (UnicodeDecodeError, CryptoError):
                    raise IntegrityError
            last_key = key
        if new_key == None or not all(c in hex_digits for c in new_key):
            raise IntegrityError
        share_info = self.storage_server.get(stored_name + "_share_info")
        if not all(c in hex_digits for c in share_info):
            raise IntegrityError
        share_info = self.crypto.symmetric_decrypt(share_info, new_key, 'AES')
        shared_users = share_info.split(',')
        invalid_stores = []
        valid_stores = []
        new_share_info = ""
        can_revoke = False
        invalid_users = []
        #goes through the tree and removes entries that are descendents of user
        for users in shared_users:
            user_info = users.split('.')
            if user_info[0] == self.username and not user_info[1] == "creator":
                return None
            if user_info[0] == user:
                if user_info[1] == self.username:
                    can_revoke = True
                invalid_stores.append(user_info[2])
            elif user_info[1] == user:
                invalid_stores.append(user_info[2])
                invalid_users.append(user_info[0])
            else:
                if new_share_info == "":
                    new_share_info += users
                else:
                    new_share_info = new_share_info + "," + users
        while len(invalid_users) > 0:
            invalid_user = invalid_users.pop(0)
            temp_share_info = ""
            for users in new_share_info.split(','):
                user_info = users.split('.')
                if user_info[1] == invalid_user:
                    invalid_users.append(user_info[0])
                else:
                    if temp_share_info == "":
                        temp_share_info += users
                    else:
                        temp_share_info = temp_share_info + "," + users
            new_share_info = temp_share_info
        if not can_revoke:
            return None
        for store in invalid_stores:
            self.storage_server.put(store + "_share_info", "")
            self.storage_server.put(store + "_keys_names", "")
        new_new_key = self.crypto.get_random_bytes(16)
        new_keys_names = ""
        for users in new_share_info.split(','):
            user_info = users.split('.')
            valid_stores.append(user_info[2])
            if new_keys_names == "":
                new_keys_names = user_info[0] + "," + str(self.crypto.asymmetric_encrypt(new_new_key, self.pks.get_public_key(user_info[0])))
            else:
                new_keys_names += "," + user_info[0] + "," + str(self.crypto.asymmetric_encrypt(new_new_key, self.pks.get_public_key(user_info[0])))

        #re-encrypt keys_names with the new key, re-encrypt share_info with new_share info, re-encrypt edit_info, tag, and value
        new_share_info = str(self.crypto.symmetric_encrypt(new_share_info, new_new_key, 'AES'))
        tag = str(self.crypto.cryptographic_hash(new_new_key + value,'SHA256'))
        for store in valid_stores:
            self.storage_server.put(store + "_keys_names", new_keys_names)
            self.storage_server.put(store + "_share_info", new_share_info)
            self.storage_server.put(store +"_tag",tag)
        number_segments = int((len(value) + seg_buffer)/seg_size)
        for n in range(1, number_segments + 1):
            ciphertext = str(self.crypto.symmetric_encrypt(value[int(n-1)*seg_size:n*seg_size], new_new_key, 'AES'))
            for store in valid_stores:
                self.storage_server.put(store + str(n), ciphertext)
                self.storage_server.put(store + str(n) + "tag", str(self.crypto.cryptographic_hash(new_key + value[int(n-1)*seg_size:n*seg_size],'SHA256'))[:4])

#DELET



