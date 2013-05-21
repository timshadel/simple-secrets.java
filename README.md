
# simple-secrets.java [![Build Status](https://travis-ci.org/timshadel/simple-secrets.java.png?branch=master)](https://travis-ci.org/timshadel/simple-secrets.java)

The Java implementation of a simple, opinionated library for encrypting small packets of data securely. Designed for exchanging tokens among systems written in a variety of programming languages: [Node.js][simple-secrets], [Ruby][simple-secrets.rb], [Objective-C][SimpleSecrets], [Java][simple-secrets.java], [Erlang][simple_secrets.erl].

[simple-secrets]: https://github.com/timshadel/simple-secrets
[simple-secrets.rb]: https://github.com/timshadel/simple-secrets.rb
[SimpleSecrets]: https://github.com/timshadel/SimpleSecrets
[simple-secrets.java]: https://github.com/timshadel/simple-secrets.java
[simple_secrets.erl]: https://github.com/CamShaft/simple_secrets.erl

## Examples

### Basic

Send:

```java
import com.timshadel.SimpleSecrets.Packet;

// Try `head /dev/urandom | shasum -a 256` to make a decent 256-bit key
Packet sender = new Packet('<64-char hex string master key (32 bytes, 256 bits)>');

Map<String, String> message = new HashMap<String, String>();
message.put( "msg", "This is a secret message!" );
String websafe = sender.pack(message);
// => "sJfaVoPxR7OSxiTNOG7_DeOQ7hzCooPdTpaR0c0MJTJZW24ule-g7JJqI5-KXt4GbAIY0jOel8HuZooWhMjW_lElOjvTjJ51T6C6r2lOPCHT5La2hEl-x9Zm9WyeIUw05XRhulDn"
```

Receive:

```java
import com.timshadel.SimpleSecrets.Packet;

// Using the same shared key
Packet sender = new Packet('<shared-key-hex>');

// Read data from somewhere (i.e. Request headers, request param, etc.)
String websafe = "sJfaVoPxR7OSxiTNOG7_DeOQ7hzCooPdTpaR0c0MJTJZW24ule-g7JJqI5-KXt4GbAIY0jOel8HuZooWhMjW_lElOjvTjJ51T6C6r2lOPCHT5La2hEl-x9Zm9WyeIUw05XRhulDn";

Map<String, String> message = sender.unpack(websafe, Map<String, String>.class);
message.get("msg")  // => "This is a secret message!"
```


## Can you add ...

This implementation follows [simple-secrets] for 100% compatibility.

## License 

MIT.