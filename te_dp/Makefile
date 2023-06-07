#**********************************************************************************************
# Traffic Emulator for Network Services
# Copyright 2020 VMware, Inc
# The BSD-2 license (the "License") set forth below applies to all parts of
# the Traffic Emulator for Network Services project. You may not use this file
# except in compliance with the License.
#
# BSD-2 License
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE
#**********************************************************************************************

CC  = gcc
CPP = g++ -std=c++11

SRCDIR = src
OBJDIR = obj
BINDIR = bin

DP_SRC   = $(wildcard $(SRCDIR)/*.c)
DP_OBJ   = $(DP_SRC:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
DP_BIN   = $(BINDIR)/te_dp
DP_FLAGS = -lcurl -luv -ljson-c -lssl -lcrypto -lpthread

STAT_SRC   = $(wildcard $(SRCDIR)/*.cpp)
STAT_OBJ   = $(STAT_SRC:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)
STAT_FLAGS = -lzmq -ljson
STAT_BIN   = $(BINDIR)/te_stats_collector

CFLAGS     = -g -O0 -Wall -I.
STAT_FLAGS = -pthread -lzmq -ljson-c

all: dp stat

dp: $(DP_OBJ)
	@$(CC) $(CFLAGS) -o $(DP_BIN) $^ $(DP_FLAGS) -no-pie
	@echo "Compiled Traffic Engine Datapath Successfully!"

stat: $(STAT_OBJ)
	@$(CPP) $(CFLAGS) -o $(STAT_BIN) $^ $(STAT_FLAGS)
	@echo "Compiled Traffic Engine Stats Collector Successfully!"

$(DP_OBJ) : $(OBJDIR)/%.o : $(SRCDIR)/%.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "Linked "$<" Successfully"

$(STAT_OBJ) : $(OBJDIR)/%.o : $(SRCDIR)/%.cpp
	@$(CPP) $(CFLAGS) -c $< -o $@
	@echo "Linked "$<" Successfully"

.PHONY: clean
clean:
	@rm -f $(DP_BIN) $(DP_OBJ) $(STAT_BIN) $(STAT_OBJ)
	@echo "Cleaned the binaries of TE's DP and Stat collector"
