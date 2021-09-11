# Bytes

```
uniformity.random/rand-bytes
([n])
  Generate an array of n cryptographically random bytes
```

### Example

```clojure
;; Java
clj꞉uniformity.random꞉> (rand-bytes 8)
#object["[B" 0x41d8ceee "[B@41d8ceee"] ; byte[]

clj꞉uniformity.random꞉> (into [] (rand-bytes 8))
[-123 -112 54 91 -122 4 -101 111]

;; JavaScript
cljs꞉uniformity.random꞉> (rand-bytes 8)
#object[Buffer �~Q�X��] ; Uint8Array

cljs꞉uniformity.random꞉> (into [] (rand-bytes 8))
[222 1 3 182 210 106 50 84]
```



# Integers

```
uniformity.random/rand-int32
([] [max] [min max])
  Returns a value between -2^31 and 2^31, exclusive of upper bound.
  When called with no argument, or one argument for upper bound,
  defaults to a lower bound of 0.
```

### Example

```clojure
clj꞉uniformity.random꞉> (rand-int32)
402798199

clj꞉uniformity.random꞉> (rand-int32 1000)
530

clj꞉uniformity.random꞉> (rand-int32 300 400)
373

clj꞉uniformity.random꞉> (rand-int32 -400 -300)
-317
```

# Booleans

```
uniformity.random/rand-bool
([])
  Returns a cryptographically random boolean
```



### Example

```clojure
clj꞉uniformity.random꞉> (rand-bool)
false
```



# Hex strings

```
uniformity.random/rand-hex-string
([n])
  Generates hex-encoded string of n bytes
```

### Example

```clojure
clj꞉uniformity.random꞉> (rand-hex-string 16)
"d56696f06e454d047debd16eae6d142d"
```



# Base64 strings

```
uniformity.random/rand-base64-string
([n])
  Generates base64-encoded string of n bytes
```

### Example

```clojure
clj꞉uniformity.random꞉> (rand-base64-string 16)
"o0qHPc5/fLK6geVGjwyzzg=="
```



# Web tokens

```
uniformity.random/rand-web-token
([n])
  Generates URL-safe base64-encoded string of n bytes
```

### Example

```clojure
clj꞉uniformity.random꞉> (rand-web-token 16)
"tzuiCDh2FVmS-YE9CxUCjQ"
```



# UUID

```
uniformity.random/rand-uuid
([])
  Generates a cryptographically random UUIDv4
```

### Example

```clojure
clj꞉uniformity.random꞉> (rand-uuid)
#uuid "e543b527-80d6-43ca-b47e-363f12e7c853"
```


# Selections

```
uniformity.random/rand-selection
([coll] [coll n])
  Returns a cryptographically random element from a collection, or a character from a string.
  Can take a count as the second argument to return a sequence of selections.
```

### Example

```clojure
clj꞉uniformity.random꞉> (def animals ["cat" "dog" "bird"
              "human" "elephant"
              "walrus" "jackalope"
              "lobster"])
#'uniformity.random/animals

clj꞉uniformity.random꞉> (rand-selection animals)
"cat"

clj꞉uniformity.random꞉> (rand-selection animals 3)
("elephant" "human" "dog")
```



# Shuffle

```
uniformity.random/rand-shuffle
([coll])
  Shuffles a collection in cryptographically random manner.
```

### Example

```clojure
clj꞉uniformity.random꞉> (rand-shuffle [1 2 3 4 5 6 7 8 9 10])
[3 8 5 7 9 4 1 2 10 6]
```


# Passwords

```
uniformity.random/rand-password
([length mask-or-opts])
  Generates password, either from a character mask (provided as string), or a collection of mask option keywords.
  Mask options:
    :upper adds A-Z
    :lower adds a-z
    :digits adds 0-9
    :special adds !@#$%^&*-_+=
    :non-ambiguous removes O01Il
```

### Example

```clojure
clj꞉uniformity.random꞉> (rand-password 8 "qwertyuiop123")
"oitrq1io"

clj꞉uniformity.random꞉> (rand-password 20
    [:upper :lower :digits :non-ambiguous])
"UZz8jKb8FNA4gwcB9TYB"
```



# Passphrases

```
uniformity.random/rand-passphrase
([length wordlist] [length wordlist delimiter])
  Generates passphrase from a wordlist, optionally taking delimiter (defaults to -).
```

### Example

```clojure
clj꞉uniformity.random꞉> (def animals ["cat" "dog" "bird"
              "human" "elephant"
              "walrus" "jackalope"
              "lobster"])
#'uniformity.random/animals

clj꞉uniformity.random꞉> (rand-passphrase 3 animals)
"jackalope-bird-cat"

clj꞉uniformity.random꞉> (rand-passphrase 3 animals "_")
"dog_jackalope_human"
```
