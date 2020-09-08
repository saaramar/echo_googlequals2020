# echo_googlequals2020

This is my solution for the echo pwn challenge from Google Quals CTF 2020. Since this challenge doesn't involve an unusual vulnerability/exploit, I won't do a full writeup on it, but I will drop the high level plan and exploit for fun:) I'll skip the introduction to the challenge, its interface and how it works - all of that is straightforward, please check out the [challenge](https://ctftime.org/task/12838) itself:)

As it turns out, the solution I have shares many similar concepts with the great solution published by *RedSocket* (check out their awesome [writeup](http://blog.redrocket.club/2020/08/30/google-ctf-quals-2020-echo/)!). For example, filling the holes created by a huge allocation of std::string by allocating sizes of decreasing powers of 2 is a classic trick we both use. However, the approach I took triggered the vulnerability twice instead of three times. Generally speaking I tend to prefer to trigger bugs as few times as possible in my exploits - in some cases this results in dramatic increase in the exploit’s stability. Specifically here we are talking about a CTF challenge with a very stable bug to exploit, so it doesn’t matter much. Anyways, it's all about the cool tricks and concepts we can do and learn! :)

This is another great opportunity to thank all of the Google CTF authors for an amazing CTF and great time, as in every year :) Keep up the fantastic work!

The challenge runs on Ubuntu 18.04, however, it uses libc-2.31 (which means tcache has some hardening, for instance the classic double-free trick doesn't hold, but the arbitrary write and the rest are still valid). For fun, I wrote two exploits -- for libc-2.31 (the actual CTF challenge) and for libc-2.28 (with the famous [double-free issue](https://twitter.com/amarsaar/status/1049658888654659584)). The flag is retrieved of course by the 2.31 exploit:

![image](https://github.com/saaramar/echo_googlequals2020/raw/master/docs/assets/final.PNG)

## The vulnerability

The challenge exposes a very straightforward vulnerability of incorrect use of iterators in C++.  In the main loop, where the challenge iterates over the *clients* std::vector, it doesn't move the iterator one place back after calling erase():

```c++
for (auto it = clients.begin(), end = clients.end(); it != end; ++it) {
        ClientCtx& client = *it;
        const int fd = client.fd;

        if (FD_ISSET(fd, &readset)) {
          if (!handle_read(client)) {
            close(fd);
            it = clients.erase(it);
            continue;
          }
        } else if (FD_ISSET(fd, &writeset)) {
          if (!handle_write(client)) {
            close(fd);
            it = clients.erase(it);
            continue;
          }
        }
      }
```

This of course creates a super exploitable scenario, as the implementation of *std::vector::erase()* is to swap the removed element and propagate it to the end of the vector, which is still inbounds of the std::vector's  heap buffer allocation, but outside of the logic bounds determined by *count* (for ref, see [this](https://stackoverflow.com/questions/45114064/how-is-stderase-implemented-for-vectors)). There are many things we can do from here, I chose to do a UAF on the std::string's buffer. POC:

* create connections s1, s2, s3 (trigger allocation of std::vector of size 4 elements, size 0x130)
* send short strings to s1, s2
* close s1
* close s2
* send data to s3 - **write to a freed std::string buffer**

In libc-2.28, tcache [had 0 integrity/security checks whatsoever](https://twitter.com/amarsaar/status/1049658888654659584). In libc-2.31, the double-free issue was mitigated, however, the arbitrary write works just like before.

## The exploit:
There are many roads to take here. I used here the classic exploitation primitives provided by tcache/dlmalloc:

* When we write a pointer to a freed chunk, we corrupt the tcache header,  which contains absolute pointer of the next allocation, hence gain **arbitrary write**
* Only libc-2.28: When we double free chunk, instead of abort, tcache will gladly return it twice upon 2 calls to malloc()
* When we free chunk from the unsorted-bins, we have in it's first bytes absolute pointers to the main arena in libc
* When a small chunk is freed, the FD/BK absolute pointers are being set accordingly with a freed chunk

So here I do the following classic exploit:

* leak an heap address
* use trivial shape to locate an unsorted chunk, free it
* gain read primitive, leak libc address
* gain arbitrary write to corrupt *(__free_hook) = system_addr



### Libc-2.31:

The exploit is pretty simple. I trigger the vulnerability only twice, in order to:

* Leak libc
* Arbitrary write *(__free_hook)=system
* PROFIT

Again, there are many roads to take here. I chose to do

#### leak libc:

* Create a number of connections, the first one (called reader) with reader->rd_buf of size 0x10000. This is because I'm about to corrupt the LSB of a heap pointer in tcache header with \x00\x00, and I want to make the next-next allocation to be allocated inside this rd_buf
* Fill holes accordingly (due to std::string reallocations)
* **Trigger vulnerability** - write to a 0x40-freed chunk -- corrupt 2 LSB bytes of heap address
* allocate s1, s2, with small buffers. S2->rd_buf is allocated inside reader->rd_buf
* send \n to reader, read reader->rd_buf, resolve offset of s2 inside it
* **Take advantage of the current memory layout for generic corruption** into entire s2 allocation, by simply writing to reader. No need to trigger the vulnerability again for that.
* Corrupt heap header, make it 0x600 size (unsorted)
* free s2, create pointer to libc inside reader->rd_buf
* send \n to reader, read reader->rd_buf, break libc base address

#### Arbitrary write

* create connections s1, s2, s3
* send short strings to s1, s2, s3
* **Trigger vulnerability** - close s1, close s2, send only 8 bytes to s3, write a pointer to the freed std::string buffer of s2, gain arbitrary write
* **corrupt *(__free_hook) = system_addr**
* PROFIT

![image](https://github.com/saaramar/echo_googlequals2020/raw/master/docs/assets/2.31_poc.PNG)



### Libc-2.28:

Here I decided to trigger the bug 3 times, just to do something cool with double-frees.

#### leak heap address:

* create connections s1, s2, s3
* send short strings to s1, s2
* **Trigger vulnerability** - close s1, close s2, send long string to s3 --> double free s2->wr_buf
* create s4 connection, send to it long string without "\n", reclaim s2->wr_buf allocation as s4->rd_buf
* create s5 connection, send to it long string without "\n", reclaim s2->wr_buf allocation as s5->rd_buf
* close s5, free s5->rd_buf, create heap address inside s4->rd_buf
* send s4 "\n", **trigger read of heap address**

#### arbitrary read, leak libc:

* create connection, send a very long string to it, close it. Created a freed unsorted bins chunk
* create connections s1, s2, s3
* send short strings to s1, s2
* **Trigger vulnerability** - close s1, close s2, send long string to s3 --> double free s2->wr_buf
* create s4, send a long string to it --> reclaim s2->wr_buf, make s4->wr_buf=s2->wr_buf
* create more connections, trigger reallocation of client std::vector's buffer, reclaim s2->wr_buf
* at this point, we have a **std::string's buffer collided with std::vector**
* corrupt s4->rd_buf with the freed unsorted chunk, contains the address of the main arena
* send s4 "\n", **leak libc address**

#### Arbitrary write:

* create connections s1, s2, s3
* send short strings to s1, s2
* **Trigger vulnerability** - close s1, close s2, send only 8 bytes to s3, write a pointer to the freed std::string buffer of s2, gain arbitrary write
* **corrupt *(__free_hook) = system_addr**
* PROFIT

Local POC (Ubuntu 18.04, libc-2.28):

![image](https://github.com/saaramar/echo_googlequals2020/raw/master/docs/assets/2.28_poc.PNG)