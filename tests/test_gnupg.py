#!/usr/bin/python
"""
Mon signed Leia's and Luke's key but not Han's
"""

import batzenca
import batzenca.gnupg
import datetime
import os
import unittest
 
class TestGnuPGQuery(unittest.TestCase):
    def setUp(self):
        gnupghome = os.environ["GNUPGHOME"] = os.path.sep.join([os.getcwd(),"tests","batzencadir","gnupg"])
        self.gnupg = batzenca.gnupg.GnuPG(gnupghome)
        
        self.leia = "4E2584FC19840E5F"
        self.han  = "DB22248C8F4C0C37"
        self.luke = int("E843C898AB0FA2FD", 16)
        self.mon  = "FABA3916FB56A97D"
        
    def test_key_get(self):
        self.assertIsNotNone( self.gnupg.key_get(self.leia) )
        self.assertIsNotNone( self.gnupg.key_get(self.han ) )
        self.assertIsNotNone( self.gnupg.key_get(self.luke) )
        self.assertIsNotNone( self.gnupg.key_get(self.mon ) )
        with self.assertRaises(batzenca.gnupg.KeyError):
            self.gnupg.key_get( "0000000000000000" )

    def test_have_secret_key(self):
        self.assertFalse( self.gnupg.have_secret_key(self.leia) )
        self.assertFalse( self.gnupg.have_secret_key(self.han ) )
        self.assertFalse( self.gnupg.have_secret_key(self.luke) )

        self.assertTrue( self.gnupg.have_secret_key(self.mon) )

        self.assertFalse( self.gnupg.have_secret_key(0) )

    def test_key_uid(self):
        name, email, comment = self.gnupg.key_uid(self.mon)
        self.assertEqual(name, "Mon Mothma")
        self.assertEqual(email, "mon@batzen.ca")
        self.assertEqual(comment, "CA")

    def test_key_okay(self):
        self.assertTrue( self.gnupg.key_okay(self.leia) )
        self.assertTrue( self.gnupg.key_okay(self.han ) )
        self.assertTrue( self.gnupg.key_okay(self.luke) )
        self.assertTrue( self.gnupg.key_okay(self.mon ) )

    def test_key_validity(self):
        self.assertEqual( self.gnupg.key_validity(self.leia), 4 )
        self.assertEqual( self.gnupg.key_validity(self.han ), 0 )
        self.assertEqual( self.gnupg.key_validity(self.luke), 4 )
        self.assertEqual( self.gnupg.key_validity(self.mon ), 5 )

    def test_key_pubkey_algos(self):
        self.assertEqual( self.gnupg.key_pubkey_algos(self.leia), ( 1,  1) )
        self.assertEqual( self.gnupg.key_pubkey_algos(self.han ), (17, 16) )
        self.assertEqual( self.gnupg.key_pubkey_algos(self.luke), ( 1,  1) )
        self.assertEqual( self.gnupg.key_pubkey_algos(self.mon ), ( 1,  1) )

    def test_key_expires(self):
        self.assertEqual( self.gnupg.key_expires(self.leia), False )
        self.assertEqual( self.gnupg.key_expires(self.han ), datetime.date(2015, 11, 17) )
        self.assertEqual( self.gnupg.key_expires(self.luke), datetime.date(2015,  5, 11) )
        self.assertEqual( self.gnupg.key_expires(self.mon ), False )

    def test_key_timestamp(self):
        self.assertEqual( self.gnupg.key_timestamp(self.leia), datetime.date(2013, 11, 17) )
        self.assertEqual( self.gnupg.key_timestamp(self.han ), datetime.date(2013, 11, 17) )
        self.assertEqual( self.gnupg.key_timestamp(self.luke), datetime.date(2013, 11, 17) )
        self.assertEqual( self.gnupg.key_timestamp(self.mon ), datetime.date(2013, 11, 17) )

    def test_key_min_len(self):
        self.assertEqual( self.gnupg.key_min_len(self.leia), 2048 )
        self.assertEqual( self.gnupg.key_min_len(self.han ), 1024 )
        self.assertEqual( self.gnupg.key_min_len(self.luke), 4096 )
        self.assertEqual( self.gnupg.key_min_len(self.mon ), 2048 )
    
    def test_key_any_uid_is_signed_by(self):
        self.assertTrue( self.gnupg.key_any_uid_is_signed_by(self.leia, self.mon) )
        self.assertTrue( self.gnupg.key_any_uid_is_signed_by(self.luke, self.mon) )
        self.assertTrue( self.gnupg.key_any_uid_is_signed_by(self.mon,  self.mon) )

        self.assertFalse( self.gnupg.key_any_uid_is_signed_by(self.han, self.mon) )

        self.assertFalse( self.gnupg.key_any_uid_is_signed_by(self.leia, self.han) )
        self.assertFalse( self.gnupg.key_any_uid_is_signed_by(self.luke, self.han) )
        self.assertFalse( self.gnupg.key_any_uid_is_signed_by(self.mon,  self.han) )

        self.assertTrue( self.gnupg.key_any_uid_is_signed_by(self.han, self.han) )

    def test_key_signatures(self):
        self.assertEqual( self.gnupg.key_signatures(self.leia), set(['4E2584FC19840E5F', 'FABA3916FB56A97D']) )
        self.assertEqual( self.gnupg.key_signatures(self.han ), set(['DB22248C8F4C0C37']) )
        self.assertEqual( self.gnupg.key_signatures(self.luke), set(['FABA3916FB56A97D', 'E843C898AB0FA2FD']) )
        self.assertEqual( self.gnupg.key_signatures(self.mon ), set(['FABA3916FB56A97D']) )

    def test_key_okay_encrypt(self):
        self.assertTrue(  self.gnupg.key_okay_encrypt(self.leia) )
        self.assertFalse( self.gnupg.key_okay_encrypt(self.han ) )
        self.assertTrue(  self.gnupg.key_okay_encrypt(self.luke) )
        self.assertTrue(  self.gnupg.key_okay_encrypt(self.mon ) )

    def test_keys_export(self):
        keys = self.gnupg.keys_export( [self.leia, self.luke] )
        self.assertTrue(keys.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----\n'))
        self.assertTrue(keys.endswith('-----END PGP PUBLIC KEY BLOCK-----\n'))

    def test_msg_sign(self):
        msg = "A long time ago in a galaxy far, far away"
        sig = self.gnupg.msg_sign(msg, self.mon)
        self.assertTrue(sig.startswith('-----BEGIN PGP SIGNATURE-----\n'))

        with self.assertRaises(ValueError):
            signature = self.gnupg.msg_sign(msg, self.leia)
        
    def test_msg_encrypt(self):
        msg = "A long time ago in a galaxy far, far away"
        ciphertext = self.gnupg.msg_encrypt(msg, [self.leia, self.luke])
        self.assertTrue(ciphertext.startswith('-----BEGIN PGP MESSAGE-----\n'))

        with self.assertRaises(ValueError):
            ciphertext = self.gnupg.msg_encrypt(msg, [self.han, self.mon])

        ciphertext = self.gnupg.msg_encrypt(msg, [self.han, self.mon], always_trust=True)
        self.assertTrue(ciphertext.startswith('-----BEGIN PGP MESSAGE-----\n'))

    def test_msg_decrypt(self):
        msg = "A long time ago in a galaxy far, far away"
        ciphertext = self.gnupg.msg_encrypt(msg, [self.leia, self.mon])
        msg2 = self.gnupg.msg_decrypt(ciphertext)
        self.assertEqual(msg, msg2)

        msg = "A long time ago in a galaxy far, far away"
        ciphertext = self.gnupg.msg_encrypt(msg, [self.leia])

        with self.assertRaises(ValueError):
            msg2 = self.gnupg.msg_decrypt(ciphertext)

    def test_sig_verify(self):
        msg = "A long time ago in a galaxy far, far away"
        sig = self.gnupg.msg_sign(msg, self.mon)
        fprs = self.gnupg.sig_verify(msg, sig)
        self.assertEqual(len(fprs), 1)
        self.assertEqual(self.mon, fprs[0][-16:])

if __name__ == '__main__':
    unittest.main()