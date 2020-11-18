include vars.mk

APP_DIR=app

CPPFLAGS := -DTOKEN_FILENAME=\"$(STEALTHDIR)/$(ENCLAVE_NAME).token\" \
			-DENCLAVE_FILENAME=\"$(STEALTHDIR)/$(ENCLAVE_NAME).signed.so\" \
			$(addprefix -I, include $(SGX_INCLUDE_PATH) $(APP_DIR))

FLAGS := -m64 -O0 -g -fPIC -Wall -Wextra -Wpedantic
CFLAGS := $(FLAGS) $(CPPFLAGS)
CXXFLAGS := $(FLAGS) $(CPPFLAGS) -std=c++11
LDFLAGS := -lsgx_urts -lpthread

.PHONY: all
all: $(APP_DIR)/app

app/%.o: app/%.cpp app/ExploitConstantAut.h
	@$(CXX) $(CXXFLAGS) -c $< -o $@
	@echo "CXX  <=  $<"

# $(APP_DIR)/enclave_u.c: $(SGX_EDGER8R) $(ENCLAVE_DIR)/enclave.edl
# 	@cd $(APP_DIR) && $(SGX_EDGER8R) --untrusted ../$(ENCLAVE_DIR)/enclave.edl
# 	@echo "GEN  =>  $@"

# $(APP_DIR)/enclave_u.o: $(APP_DIR)/enclave_u.c
# 	@$(CC) $(CFLAGS) -c $< -o $@
# 	@echo "CC   <=  $<"

$(APP_DIR)/app: $(APP_DIR)/enclave_u.o $(APP_DIR)/app.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "CC extension <=  $<"
	@mkdir -p $(BUILD_DIR)

$(STEALTHDIR):
	mkdir -p $@

.PHONY: clean
clean:
	@$(RM) $(CXX_OBJS) $(C_OBJS) $(APP_DIR)/enclave_u.* $(APP_DIR)/app
