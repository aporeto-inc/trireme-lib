Contributing
------------

As an open source project, your contributions are important to the future of Trireme. Whether you're looking to write code, add new documentation, or just report a bug, you'll be helping everyone who uses Trireme in the future.

### Reporting Bugs

Filing issues is a simple but very important part of contributing to Trireme. It provides a metric for measuring progress and allows the community to know what is being worked on. "Issues" in the context of the project refer to everything from broken aspects of the framework, to regressions and unimplemented features. Trireme uses [GitHub Issues](https://github.com/aporeto-inc/trireme/issues) for tracking issues!

When opening an issue or a pull request, labels will be applied to it. You can check the Issue and Pull Request Lifecycle [here](https://github.com/aporeto-inc/trireme/wiki/Issue-and-Pull-Request-Lifecycle).

### Contributing to the project

There are always bugs to be fixed and features to be implemented, some large, some small. Fixing even the smallest bug is enormously helpful! If you have something in mind, don't hesitate to create a pull request [here](https://github.com/aporeto-inc/trireme/pulls)!

When contributing to a project you must propose a pull request for each modifications you do.
To do a PR, please follow this instructions :

```bash
git checkout master #make sure your base is the master
git checkout -b nameOfYourNewBranch #create a new branch and start to work locally on this branch

... #do your change

./.test.sh

git add yourFile* #add the files to the commit
git commit #create a beautiful messages for the commit, please follow the guideline below
git push origin nameOfYourNewBranch #push the branch on the remote origin
```

Then we advise to create your PR from the github website, make sure to read your changes again.
More documentation here : https://git-scm.com/documentation

Pull requests will not be accepted if the tests are not passing and if the coverage of the tests has dicreased.

### Coding Guidelines

Go Coding Style Guidelines
You must follow the golint, gofmt guide style when coding in Go. You must also know by heart Effective Go.
Install the linter on your system and add it to your pre-commit hook.

### Do's and don'ts

DO
* Be consistent.
* Use symmetry. If you provide a way to do something, provide a way to undo it.
* All public methods and functions must be commented.
* A comment has a space between // and the first letter.
* A comment starts with a capitalized letter and ends with a final dot.
* Be careful with the commenting. This could be released to GoDoc at anytime.
* An interface or a struct Thing comment should be in the form of "// A Thing is a thing", not "// Thing is a thing"
* Code must go straight to the point. Do not over engineer by thinking "maybe one day". If that day comes, update your code.
* Use short explicit name for variables. "objectThatMayBeCreatedIfEverythingIsFine" is overkill. "obj" is enough. Use best judgement.
* A function must do what its name says. "catchPokemon(pokeball) bool" should not get an int as parameters, and do an addition.
* Organize your packages consistently.
* Skip a line between the function declaration and the first line of code.
* A constructor must use the "return &Struct{a: 1}" pattern, not "newthing:= &Struct{}; thing.a = 1; return a".
* Always provide a way to understand what went wrong or what went well in a function/method. A log is useless.
* A function or method that starts by "Is" or "Are" must return a boolean.
* Order of appearance of methods should be consistent:
* Imports
* Constants (if any)
* Variables (if any)
* Helper functions (if any)
* Main structure
* Constructor (if any)
* Implemented interface methods (if any)
* Public methods (if any)
* Private methods (if any)

DON'T

* Do not write more than a main structure per file.
* Do not ignore returned errors. Never. Handle them, or pass them back. You can use github.com/kisielk/errcheck to help you find them.
* Do not over log. Go philosophy is "no news, good news". Carefully minimize all logs above the "debug" level.
* Do not put logs in a helper functions. Return an error and let the main program decide what to do.
* Don't use new().
* Do not pass entire structure down, because at some point you need one value. Just pass the value. (see "maybe one day" point)
* Do not export methods if they are not used outside of the package (see "maybe one day" point)
* Do not let an unused function in the code, delete it. Use Go Oracle to find the referrers if needed. (if we need it later, git is our friend)
* Do not let Todos hanging in the code forever. Fix them asap.
* Do not overuse wrappers. If a library provides a structure that matches what you need, use it  (see "maybe one day" point).
* Do not store duplicate information: a.Name = b.Name, a.B = b. a.B.Name is enough
* Don't use strings. Strings are bad for anything else than giving information to a human. Use a constant or a structure.
* Do not copy and paste business logic code. If you need the same code twice, write a function.
* Do not use map[string]map[string]chan map[string]bool, create a Type.
* Do not pass information through maps. Maps content cannot be controlled by the compiler (see "don't use string" point)
* Do not overused go routines. Remember that if someone wants to thread something, he can use "go" himself. Leave the guy a choice.
* Do not let old naming. If a structure doesn't do what it did in the beginning, rename it. gorename is our friend here.
* Do not paste StackOverflow code without understanding exactly what it does. You should also add a backlink.

### Commit Messages

The style and format of your commit messages are very important to the health of the project. A good commit message helps not only users reading the release notes, but also your fellow developers as they review git log or git blame to figure out what you were doing.

Commit messages should be in the following format:

```
#comments
<type>: <summary>
<body>
<footer>
<transition-state >
```

### Types

* Allowed type values are:
* New — A new feature has been implemented
* Fixed — A bug has been fixed
* Docs — Documentation has been added or tweaked
* Formatting — Code has been reformatted to conform to style guidelines
* Test — Test cases have been added
* Task — A build task has been added or updated

### Message summary

The summary is one of the most important parts of the commit message, because that is what we see when scanning through a list of commits, and it is also what we use to generate change logs.
The summary should be a concise description of the commit, preferably 72 characters or less (so we can see the entire description in github), beginning with a lowercase letter and with a terminating period. It should describe only the core issue addressed by the commit. If you find that the summary needs to be very long, your commit is probably too big! Smaller commits are better.

For a New commit, the summary should answer the question, “What is new and where?” For a Fixed commit, the summary should answer the question, “What was fixed?”, for example “Wrong Python version in Kafka Dockerfile”. It should not answer the question, “What was done to fix it?” That belongs in the body.

Do not simply reference another issue or pull request by number in the summary. First of all, we want to know what was actually changed and why, which may not be fully explained in the referenced issue. Second, github will not create a link to the referenced issue in the commit summary.

### Message body

The details of the commit go in the body. Specifically, the body should include the motivation for the change for New, Fixed and Task types. For Fixed commits, you should also contrast behavior before the commit with behavior after the commit.
If the summary can completely express everything, there is no need for a message body.

### Message footer

If the commit closes an issue by fixing the bug, implementing a feature, or rendering it obsolete, or if it references an issue without closing it, that should be indicated in the message footer.
Issues closed by a commit should be listed on a separate line in the footer with an appropriate prefix:
"Fixes" for Fixed commit types
"Closes" for all other commit types
For example:

```
Fixes #1234
```

or in the case of multiple issues, like this:

```
Fixes 1234, 2345
```

Issues that a commit references without closing them should be listed on a separate line in the footer with the prefix "Refs", like this:

```
Refs #1234
```

or in the case of multiple issues, like this:

```
Refs #1234, #2345
```

If a commit changes the API or behavior in such a way that existing code may break, a description of the change, what might break, and how existing code should be modified must be noted in the footer like this:

```
BREAKING CHANGE:
Dockerfile of Kafka has been changed, you must generate a new image of Kafka.
```

### Examples

```
Fixed: Wrong Python version in Kafka Dockerfile

Previously, the Kafka's Dockerfile installed the version 3.0 of Python. This version of Python
did not work with the lib configobj.

We now make sure to install the version 2.7 of Python by specifying the version when installing
Python.

Fixes 1234
```
