/*
 * Copyright (c) 2007 Johann Klasek
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by Johann Klasek
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * fd_pool.h  Stdio stream function replacement for limited stdio implementations
 *
 * 2007-06-04 Johann E. Klasek, johann at klasek at
 *
 */

#ifdef USE_FD_POOL

#include <stdio.h>

extern int fd_pool_init(void);
extern int fclose_ext(FILE *stream);
extern FILE *fdopen_ext(int fd, char *mode);
extern FILE *fopen_ext(char *path, char *mode);

# define Fopen(path,mode) fopen_ext(path,mode)
# define Fdopen(fd,mode) fdopen_ext(fd,mode)
# define Fclose(stream) fclose_ext(stream)

#else

# define Fopen(path,mode) fopen(path,mode)
# define Fdopen(fd,mode) fdopen(fd,mode)
# define Fclose(stream) fclose(stream)

#endif
