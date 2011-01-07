#!/usr/bin/env python -tt
import sys;
import unittest;
import urllib2;
import json;

from OAuthSimple import OAuthSimple

class TestOAuth(unittest.TestCase):
    
    signatures = {'consumer_key':'v9s778n692e9qvd83wfj9t8c','shared_secret':'54XqbMADta'};
    test_url = 'http://api.netflix.com/catalog/titles';
    parameters = 'term=mac%20and+me&expand=formats,synopsis&max_results=1&v=2.0&output=json';
    
    def setUp(self):
        self.o1 = OAuthSimple()
        
    def testUtils(self):
        self.assertEqual(self.o1._oauthEscape('a b+c!d*\\e(f)g+h'),'a%20b%2Bc%21d%2A%5Ce%28f%29g%2Bh');
        self.assertEqual(self.o1._arrayMerge({'a':0,'b':2,'c':3},{'a':1,'d':4}),{'a':1,'b':2,'c':3,'d':4});
        self.o1.signatures({'api_key':'123','shared_secret':'456'})
        self.o1.setParameters({'a':1,'b':2});
        self.assertEqual(self.o1._secrets['oauth_consumer_key'],'123');
        self.assertEqual(self.o1._secrets['shared_secret'],'456')
        self.assertEqual(len(self.o1._getNonce(10)),10);
        self.assertNotEqual(self.o1._getNonce(),self.o1._getNonce())
        self.o1.reset();
        self.assertTrue(len(self.o1._parameters)==0)

    def testSimple(self):
        self.o1.reset();
        signed = self.o1.sign({'signatures':self.signatures,'parameters':self.parameters,'path':self.test_url});
       # import pdb; pdb.set_trace();
        self.assertTrue(len(signed.get('signature')) > 0)
        self.assertTrue(len(signed.get('signed_url'))>0)
        # send the link.
        try:
            rsp=urllib2.urlopen(signed.get('signed_url'))
        except urllib2.HTTPError as ex:
            if (ex.headers.get('x-mashery-error-code') == 'ERR_401_TIMESTAMP_IS_INVALID'):
                print "Your clock is off. Check and retry."
                raise
            print ex
            raise
        content = json.loads(rsp.read())
        self.assertTrue(content.get('catalog')[0].get('id') == u'http://api.netflix.com/catalog/titles/movies/60035973')
    
    def testComplex(self):
        self.o1.reset();
        self.o1.signatures(self.signatures);
        self.o1.setPath(u'http://api.netflix.com/catalog/titles/movies/60035973');
        self.o1.setParameters({'expand':'all',
                               'v':'2.0',
                               'output':'json'});
        signed = self.o1.sign();
        content = json.loads(urllib2.urlopen(signed.get('signed_url')).read())
        # This is probably testing Netflix's API more than mine.
        self.assertEqual(content['catalog_title']['directors'][0]['name'],u'Stewart Raffill')
        
       
if (__name__ == '__main__'):
    unittest.main()
    
