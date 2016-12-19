# SPAM = Simple PAssword Manager 

The jar needs to be run from inside SPAM folder created in 'target'.

How secure is it?
The implementation relies on AES-256 encryption provided by BouncyCastle and SUN JCE,
it leverages CBC and Padding, generated key length is 32 bytes (256 bits).

Example:

```
cd target/SPAM
java -jar com.softinite.spam-1.1.jar -file storage.spam -list
```

### Dependencies
1. Java >= 1.8
2. JCE (please google 'How to install JCE for Java X', where X is your version of Java)

### Disclaimer
```
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, A
RISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
```