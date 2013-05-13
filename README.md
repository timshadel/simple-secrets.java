
# simple-secrets.java [![Build Status](https://travis-ci.org/timshadel/simple-secrets.java.png?branch=master)](https://travis-ci.org/timshadel/simple-secrets.java)

The Java implementation of a simple, opinionated library for encrypting small packets of data securely. Designed for exchanging tokens among systems written in a variety of programming languages: [Node.js][simple-secrets], [Ruby][simple-secrets.rb], [Objective-C][SimpleSecrets], [Java][simple-secrets.java].

[simple-secrets]: https://github.com/timshadel/simple-secrets
[simple-secrets.rb]: https://github.com/timshadel/simple-secrets.rb
[SimpleSecrets]: https://github.com/timshadel/SimpleSecrets
[simple-secrets.java]: https://github.com/timshadel/simple-secrets.java

## Examples

### Basic

Send:

```java
import com.timshadel.SimpleSecrets.Packet;

// Try `head /dev/urandom | shasum -a 256` to make a decent 256-bit key
Packet sender = new Packet('<64-char hex string master key (32 bytes, 256 bits)>');
// => #<Packet@5e8fce95>

Map<String, String> message = new HashMap<String, String>();
message.put( "msg", "this is a secret message" );
String websafe = sender.pack(message);
// => "Qr4m7AughkcQIRqQvlyXiB67EwHdBf5n9JD2s_Z9NpO4ksPGvLYjNbDm3HRzvFXFSpV2IqDQw_LTamndMh2c7iOQT0lSp4LstqJPAtoQklU5sb7JHYyTOuf-6W-q7W8gAnq1wCs5"
```

Receive:

```java
import com.timshadel.SimpleSecrets.Packet;

// Same shared key
Packet sender = new Packet('<shared-key-hex>');
// => #<Packet@ce955e8f>
// Read data from somewhere
String websafe = "OqlG6KVMeyFYmunboS3HIXkvN_nXKTxg2yNkQydZOhvJrZvmfov54hUmkkiZCnlhzyrlwOJkbV7XnPPbqvdzZ6TsFOO5YdmxjxRksZmeIhbhLaMiDbfsOuSY1dBn_ZgtYCw-FRIM";

Object secret_message = sender.unpack(websafe);
// => {
//      msg: "this is a secret message"
//    }
```


## Can you add ...

This implementation follows [simple-secrets] for 100% compatibility.

## License 

MIT.