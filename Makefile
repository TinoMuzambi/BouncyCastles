JFLAGS = -g -classpath ../lib/bc-fips-1.0.2.3.jar -d ../bin
JC = javac
JVM= java
FILE=
.SUFFIXES: .java .class
.java.class:
    $(JC) $(JFLAGS) $*.java
CLASSES = \
    KeyWithMessageDigest.java \
    Hashing.java \
    Encryption.java \
    HashingAndEncryption.java \
    ClientHandler.java \
    Client.java \
    ClientRunner.java \
    Server.java

default: classes

classes: $(CLASSES:.java=.class)

client:
	$(JVM) ClientRunner

server:
	$(JVM) Server

clean:
	rm ./bin/*.class