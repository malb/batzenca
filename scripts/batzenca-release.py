#!/usr/bin/python
# -*- coding: utf-8 -*-
from batzenca import *
from batzenca.util import publish, thunderbird_rules, gpgconf_rules

publish(debug=False, attach=[thunderbird_rules, gpgconf_rules])
