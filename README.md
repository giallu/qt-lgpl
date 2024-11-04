# Qt LGPL

Let's face it: building Qt in all the platforms is a hassle. 

Not only one needs to find the correct set of dependecies to install, divine which of the dozens configure options to use, deal with not so easy to diagnose configuration errors, and then spend a considerable amount of time compiling all the code, but the license for Qt code is (purposefully?) complicated: if you are developing a GPL application you are in luck, all the code in Qt is compatible with that license.

Things gets "interesting" when you want to keep you application's code closed: in this case you are left with paying Qt company for the commercial license (which will give you access to all the modules but taints your code with "developed with Qt commercial" status, this can't be undone) or stick to the LGPL modules; this repository tries to help in this latter case.

You will find here pre-built Qt binaries with ONLY LGPL licensed modules you can use and distribute with your project ; please refer to the [LGPL license](http://www.gnu.org/licenses/lgpl-3.0.html) for all the details.

If you find something missing or not generally correct, feel free to [open an issue](https://github.com/giallu/qt-lgpl/issues/new)

## Qt commercial license
[Qt Group's license terms](https://www.qt.io/terms-conditions/qt-dev-framework) did change (and still do) from time to time, so if you are planning to rely on the Qt library for a commercial activity I suggest you invest in some quality legal advice before choosing Qt and one of the possible licenses.

I am not a lawyer but I've dealt with their license terms long enough so I will try save you some time by summarizing here what I know about it:

1. you need to choose early if you will use the GPL or LGPL license and stick with it. Their license explicitly calls "Prohibited Combination" mixing code developed with (L)GPL and commercial license; this means you can't start with (L)GPL and later acquire the Commercial license to work on the same project (however, I guess if you ask them they will allow it, not sure if and how much that will cost you). This also means you can't have people working on the same project if some of them use the Commercial version: all of them will need a Commercial license.

2. as a corollary to 1, if you started a project with the Commercial license then all of the code you will ever add to it have to come from contributors owning a Commercial license. And someone said GPL was viral...

3. there is a distinction between Application and Devices development when it comes to distribution: software distributed with devices is subject to a royalty.

Summing up: if you are going to create some desktop software based on Qt and you plan to distribute it (for free or for a fee), you can choose to use the LGPL version of Qt you can find here, but be careful to avoid "tainting" the sources with contributions made with Qt Commercial.

## So what can I use these binaries for?

Again, I am not a lawyer so I recommend you consult with a real one if you are going to use Qt for professional purposes.

However, the LGPL license is widespread since ages, so its strenghts and limitations are well known. Summarizing:

1. if you modify and redistribute binaries of the library (out of the scope of my repository, these binaries are compiled from pristine upstream source) you need to provide the corresponding source code.
2. if you link statically against LGPL code your work falls under the LGPL as well, so you would need to release the corresponding source code (again out of scope, I only provide here dynamic -aka shared- libraries)
3. if you link dynamically with LGPL code you don't need to release your sources and the resulting combination can be distributed for free or for a fee

## How to use the binaries
TODO
