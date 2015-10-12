# KerberosLikeFileSharingSystem

![alt tag](https://raw.githubusercontent.com/mfso1991/KerberosLikeFileSharingSystem/master/protocols.png)

Notice that the document namely ```Phase1&2_DOC.pdf``` only demonstrates a subset of the functionalities. I can't find the complete one after so long ...

goto /src

compile as ```javac -cp bcprov-ext-jdk15on-153.jar *.java ```

in the first terminal run ```java -cp .:bcprov-ext-jdk15on-153.jar RunGroupServer```

in the second terminal run ```java -cp .:bcprov-ext-jdk15on-153.jar RunFileServer```

in the third terminal run ```java -cp .:bcprov-ext-jdk15on-153.jar ClientApp```

You can open as many terminal as you want to run ```ClientApp``` since there should be a bounch of users to make sense for this project :)

Following instructions, you will be fine.

Operations you can do in ClientApp:

				"lf   : List all files you have access to.";
				"df   : Delete file shared in group.";
				"up   : Upload a file to share with a group.";
				"down : Download a file you have access to.";
				"lm   : List members of an owned group. | Owner only.";
				"cp   : Change Password.";
				"cu   : Create a new user. | Admin only.";
				"du   : Delete a user. | Admin only.";
				"cg   : Create a new group.";
				"dg   : Delete a group. | Owner only.";
				"ug   : Add a user to an existing group. | Owner only.";
				"gu   : Remove a user from group. | Owner only.";

 
