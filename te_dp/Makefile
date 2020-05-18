CC  = gcc
CPP = g++ -std=c++11

SRCDIR = src
OBJDIR = obj
BINDIR = bin

DP_SRC   = $(wildcard $(SRCDIR)/*.c)
DP_OBJ   = $(DP_SRC:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
DP_BIN   = $(BINDIR)/te_dp
DP_FLAGS = -lcurl -luv -ljson -lssl -lpthread

STAT_SRC   = $(wildcard $(SRCDIR)/*.cpp)
STAT_OBJ   = $(STAT_SRC:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)
STAT_FLAGS = -pthread -lzmq -ljson
STAT_BIN   = $(BINDIR)/te_stats_collector

CFLAGS     = -g -O0 -Wall -I.
STAT_FLAGS = -pthread -lzmq -ljson

all: dp stat

dp: $(DP_OBJ)
	@$(CC) $(CFLAGS) -o $(DP_BIN) $^ $(DP_FLAGS)
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
