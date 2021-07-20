#!/bin/sh
# This is libnet coding style, rediscovered by inspecing various key
# files: libnet_build_ip.c, libet_init.c, ... it is what it is, and we
# don't enforce it.  Treat it only as a guide when contributing.  When
# changing existing code, first and foremost, follow the style in that
# file.
#
# With the -T foo we can inform indent about non-ansi types that we've
# added, so indent doesn't insert spaces in odd places.  We should add
# all the libnet types here (todo)
indent \
    --preserve-mtime \
    --break-after-boolean-operator \
    --blank-lines-after-declarations \
    --blank-lines-after-procedures \
    --braces-after-if-line \
    --braces-after-struct-decl-line \
    --brace-indent0 \
    --case-indentation4 \
    --case-brace-indentation0 \
    --comment-indentation53 \
    --continue-at-parentheses \
    --declaration-indentation2 \
    --dont-break-function-decl-args \
    --dont-break-procedure-type \
    --dont-cuddle-do-while \
    --dont-cuddle-else \
    --dont-format-comments \
    --honour-newlines \
    --ignore-profile \
    --indent-level4 \
    --leave-optional-blank-lines \
    --leave-preprocessor-space \
    --line-length132 \
    --no-blank-lines-after-commas \
    --no-space-after-parentheses \
    --no-space-after-function-call-names \
    --no-tabs \
    --no-space-after-casts \
    --space-after-if \
    --space-after-for \
    --space-after-while \
    --procnames-start-lines \
    -T size_t -T sigset_t -T timeval_t -T pid_t -T pthread_t -T time_t \
    -T uint64_t -T uint32_t -T uint16_t -T uint8_t \
    -T int64_t -T int32_t -T int16_t -T int8_t \
    -T uchar -T uint -T ulong -T ushort -T u_short -T u_int \
    $*
