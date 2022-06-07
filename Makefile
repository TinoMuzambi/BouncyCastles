JFLAGS = -g -classpath ./lib/bc-fips-1.0.2.3.jar:./bin -d ./bin -sourcepath ./src
JC = javac
JVM= java
FILE=
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java
CLASSES = src/Utils.java src/KeyWithMessageDigest.java src/Hashing.java src/Encryption.java src/HashingAndEncryption.java src/ClientHandler.java src/Client.java src/ClientRunner.java src/Server.java

default: classes

classes: $(CLASSES:.java=.class)

client:
	$(JVM) -classpath ./lib/bc-fips-1.0.2.3.jar:./bin ClientRunner

server:
	$(JVM) -classpath ./lib/bc-fips-1.0.2.3.jar:./bin Server

clean:
	rm -rf ./bin/*.class

docs:
	javadoc  -classpath ./lib/bc-fips-1.0.2.3.jar:./bin -d ./doc ./src/*.java

cleandocs:
	rm -rf ./docs/*