## Dog Shelter 

```
à¸…^â€¢ï»Œâ€¢^à¸…
The binary can be run with the provided libc
version by for example using LD_PRELOAD on Linux.

Provided file: dogshelter.tgz (contains binary and libc)
```

### Short description of program

Dog Shelter is a program that you can add (addDog), edit (editDog), release (releaseDog) and view (viewDogs) the added dogs. You can add a dog by specifying the name and age, and it is possible to edit their name and age afterwards. The dogs are managed using the heap memory.

### Bug

The program's releaseDog function has a problem that it does not check if the dog at the specified index is valid, and it does not set the dog pointer to NULL after releasing it. This can be exploited to cause double-free.

### Exploit

The dogs have a structure like:
```
struct Doge
{
	int age;
	char *name;
};
```
(Note: Since it is 64-bit application the char pointer is 8 byte, and age will be padded to 8 byte, so sizeof(Doge) = 16)

A snippet of pseudo code for addDog is something like:
```
Doge *dog = malloc(sizeof(Doge))
...
dog->name = malloc(strlen(buf))
```

and for releaseDog:

```
free(dog-name);
free(dog);
```

Understanding the order things gets allocated/freed is important to exploit the bug.

If a struct A object gets freed the address will be stored in freelist (a linked list structure), and later if same size of allocation is called the malloc function will pick up the pointer from freelist and return it to caller. The double-free vulnerability can cause one pointer to appear multiple times freelist, and allocating multiple objects (not neccesary same type) will lead multiple objects to point at same address. A much better (and correct) explanation about these things can be found here: https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/

So how can this be exploited?
Allocate two dogs, let the first one have the name AAA... (16 A:s) and second one BBB... (40 B:s)
Release the first dog, the freelist will look like:

```
dog_name_0 <- dog_struct_0 <- freelist
```

then release second dog, the freelist should look like:
```
dog_name_0 <- dog_struct_0 <- dog_struct_1 <- freelist
```
(dog_name_1 is placed in another freelist because it is larger)

and then releasing the first dog again will make freelist look like:

```
dog_name_0 <- dog_struct_0 <- dog_struct_1 <- dog_name_0 <- dog_struct_0 <- freelist
```

Now what happens if you allocate two dogs?
It will result in something like:

```
Doge *dog0 = dog_struct_0;
dog0->name = dog_name_0;

Doge *dog1 = dog_struct_1;
dog1->name = dog_struct_0;
```

The first one looks fine but second dog's name ptr is pointing at dog0's struct!
Now you can just overwrite dog0's structure using editDog function, and make so char ptr points at GOT (free function in my case) so calling viewDogs leaks libc address. Then calculate the system function address and overwrite the GOT with it. If things are done correctly you should get the shell.
