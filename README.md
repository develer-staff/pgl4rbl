## PGL4RBL: Greylisting on RBL (DNS blacklist) for Postfix

This package implements a Postfix policy server that mixes two widely used techniques: greylisting and RBL (DNS blacklists). The idea is that greylisting is applied only to SMTP clients that match a RBL; this means that normal clients are not delayed (such as with a normal greylisting implementation), and RBL false positives do not cause problems (like when outright blocking them at the SMTP level).

More information can be found in this [blog post](http://giovanni.bajo.it/post/47121521214/grey-on-black-combining-greylisting-with-blacklists).

### Installation

Install pgl4rbl somewhere on the local Postfix filesystem, for instance:

    $ cd /usr/local
    $ git clone https://github.com/develersrl/pgl4rbl

Copy `pgl4rbl.conf` to `/etc/mail`:

    $ cp /usr/local/pgl4rbl/pgl4rbl.conf /etc/mail

Then, open it and have a look. All defaults are meant to be reasonable and correct, but you are welcome to change them if you want.

Now, tell Postfix to start pgl4rbl as a service, by editing `/etc/postfix/master.cf` and adding this line to it:

```
# greylisting on rbl
rbl_grey unix  -       n       n       -       0       spawn
        user=pgl4rbl argv=/usr/bin/python /usr/local/pgl4rbl/pgl4rbl.py
```

Then, in `/etc/postfix/main.cf`, within the section `smptd_recipient_restrictions`, add the following line:

    check_policy_service unix:private/rbl_grey

Finally, reload postfix:

    $ postfix reload


### Example of full anti-spam configuration

For instance, the following section shows a sample anti-spam configuration with several rules:

```
smtpd_recipient_restrictions =
        permit_mynetworks
        permit_sasl_authenticated
        permit_dnswl_client list.dnswl.org
        reject_rbl_client sbl.spamhaus.org
        reject_rbl_client psbl.surriel.com
        reject_unauth_destination
        reject_unlisted_recipient
        check_policy_service unix:private/rbl_grey
```

This is what happens, step by step:

 * If the client's IP is in `mynetworks`, mail is delivered.
 * If the client has authenticated, mail is delivered.
 * If the client's IP is in the <dnswl.org> whitelist, mail is delivered.
 * If the client's IP is in either the [Spamhaus SBL](http://www.spamhaus.org/sbl/) or [PSBL](http://psbl.org/) blacklists, the mail is rejected (500).
 * If the mail destination's domain is not directly handled by Postfix, mail is rejected (= disable relay).
 * If the mail destination's email is not a valid email address, mail is rejected.
 * Otherwise, the mail is handled by pgl4rbl; it will check whether the client's IP is in one of the configured RBLs

### How to choose blacklists

The default configuration of pgl4rbl includes the following blacklists:

 * [xbl.spamhaus.org](http://www.spamhaus.org/xbl/): list of hijacked PCs (aka "zombies")
 * [pbl.spamhaus.org](http://www.spamhaus.org/pbl/): list of consumer IP ranges, that shouldn't run mail servers
 * [bl.spamcop.net](http://www.spamcop.net): list of IPs which sent spam (as reported by a large community of volunteers)
 * [dnsbl.sorbs.net](http://www.sorbs.net): list of IPs which sent spam to a set of honeypots / spam traps

In our experience, outright rejection of email through these blacklists would be too hard, while their usage within pgl4rbl achieves a very good balance.





