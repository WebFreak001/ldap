# ldap

Cross platform Microsoft Active Directory client using LDAP (winldap on windows, openldap otherwise).

Openldap implementation based off [dopenldap](https://github.com/ikod/dopenldap)

```d
import std.stdio;

int proto_version;

auto ldap = LDAPConnection("127.0.0.1:389"); // normal ldap connection
auto auther = LDAPAuthenticationEngine("127.0.0.1:389"); // ldap connection with fast binding and no encryption support on windows (used for password authentication)
ldap.getOption(LDAP_OPT_PROTOCOL_VERSION, &proto_version);
if (proto_version == 2)
{
	proto_version = 3;
	ldap.setOption(LDAP_OPT_PROTOCOL_VERSION, &proto_version);
	writeln("Switched to protocol version 3");
}

ldap.bind("admin@localhost", "");

auto arr = ldap.search("OU=data,DC=data,DC=local",
		LDAP_SCOPE_SUBTREE, "(|(objectClass=contact)(objectClass=user))", ["l"]); // find all users & contacts

writefln("Found %s results", arr.length);
foreach (r; arr)
{
	writeln(r.distinguishedName); // print path of contact
	foreach (k, v; r.attributes)
	{
		writef("%s = %s", k, v); // prints location of contacts (because of ["l"] argument above)
	}
}
writeln("Done");

assert(!auther.check("non valid user", "non valid password"));
assert(auther.check("admin", ""));
```