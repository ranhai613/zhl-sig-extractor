# @category Ghidra
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.address import Address
from ghidra.program.model.lang import OperandType
from ghidra.program.model.scalar import Scalar
from ghidra.util.task import ConsoleTaskMonitor
import os
import jarray

TARGET_NAMESPACES = ["AchievementTracker","Animation","AnimationControl","AnimationTracker","ArmamentControl","ArtilleryBox","ArtillerySystem","Asteroid","AsteroidGenerator","AugmentEquipBox","AugmentStoreBox","BatteryBox","BeamWeapon","Blueprint","BlueprintManager","BoarderDrone","BoarderPodDrone","BombProjectile","BossShip","Button","CachedImage","CachedPrimitive","CachedRect","CAchievement","CApp","CEvent","CFPS","ChoiceBox","ChoiceText","CloakingBox","CloakingSystem","CloneBox","CloneSystem","CombatAI","CombatControl","CombatDrone","CommandGui","CompleteShip","ConfirmWindow","ControlButton","ControlsScreen","CooldownSystemBox","CreditScreen","CrewAI","CrewAnimation","CrewBlueprint","CrewBox","CrewControl","CrewCustomizeBox","CrewDrone","CrewEquipBox","CrewLaser","CrewManifest","CrewMember","CrewMemberFactory","CrewStoreBox","CrewTarget","CrystalAlien","CSurface","Damage","DamageMessage","DebugHelper","DefenseDrone","Description","Door","DoorBox","Drone","DroneBlueprint","DroneControl","DroneStoreBox","DroneSystem","DropBox","EffectsBlueprint","EnergyAlien","Equipment","EquipmentBox","EquipmentBoxItem","EventGenerator","EventsParser","EventSystem","ExplosionAnimation","FileHelper","Fire","FocusWindow","freetype","FTLButton","GameOver","GenericButton","Global","Globals","GL_Color","GL_Line","HackBox","HackingDrone","HackingSystem","InfoBox","InputBox","IonDrone","IonDroneAnimation","ItemStoreBox","LanguageChooser","LaserBlast","LocationEvent","LockdownShard","MainMenu","MantisAnimation","MenuScreen","MindBox","MindSystem","Missile","MouseControl","OptionsScreen","OuterHull","OxygenSystem","PDSFire","Point","Pointf","PowerManager","Projectile","ProjectileFactory","ReactorButton","RepairAnimation","RepairStoreBox","ResourceControl","RockAlien","RockAnimation","Room","ScoreKeeper","Settings","SettingValues","Shields","Ship","ShipAI","ShipBlueprint","ShipBuilder","ShipButton","ShipEvent","ShipGenerator","ShipGraph","ShipInfo","ShipManager","ShipObject","ShipSelect","ShipStatus","ShipSystem","SoundControl","SpaceDrone","SpaceManager","SpaceStatus","Spreader_Fire","StarMap","StatusEffect","Store","StoreBox","SuperShieldDrone","SystemBox","SystemControl","SystemCustomBox","SystemStoreBox","TabbedWindow","TeleportBox","TeleportSystem","TextButton","TextInput","TextLibrary","TextString","TimerHelper","TopScore","TutorialManager","UnlockArrow","UpgradeBox","Upgrades","WarningMessage","WeaponAnimation","WeaponBlueprint","WeaponBox","WeaponControl","WeaponEquipBox","WeaponStoreBox","WeaponSystem","WeaponSystemBox","WindowFrame","WorldManager"]

class FunctionInfoBase(object):
    def __init__(self):
        self.raw_sig = None
        self.sig_length = None
        self.no_return_seek = False
        self.no_chain = False
        self.unique = True
        self.failed = False

class FunctionInfo(FunctionInfoBase):
    def __init__(self, func, class_name):
        FunctionInfoBase.__init__(self)
        self.func = func
        self.class_name = class_name
        self.ret_address = None
        self.dummy_hook = None
    
    def OutputZHLSignature(self):
        if self.failed:
            return "// Failed to generate signature for function: {}::{} at {}\n".format(self.class_name, self.func.getName(), self.func.getEntryPoint())
        
        ret = ""
        if self.dummy_hook is not None:
            ret += self.dummy_hook.OutputZHLSignature()
        
        # Generate signature string
        sig = ""
        if self.no_return_seek:
            sig += "!"
        if not self.no_chain:
            sig += "."
        sig += self.raw_sig.lower().replace(" ", "")
        
        return_type = self.func.getReturnType().getDisplayName()
        
        params = self.func.getParameters()
        param_list = []
        for p in params:
            p_type = p.getDataType().getDisplayName()
            p_name = p.getName()
            param_list.append("{} {}".format(p_type.strip(), p_name.strip()))

        args = "({})".format(", ".join(param_list))
        
        is_static =  len(params) == 0 or params[0].getName() != "this"
        
        # 1st line: signature line
        ret += "\"{}\": ".format(sig)
        if self.unique:
            ret += " // unique sig\n"
        else:
            ret += " // non-unique sig\n"

        # 2nd line: function prototype
        if is_static:
            ret += "static "
        ret += "cleanup __amd64 {} {}::{}{}; // {}\n".format(return_type, self.class_name, self.func.getName(), args, self.func.getEntryPoint())
        return ret
        

class NoHook(FunctionInfoBase):
    def __init__(self, class_name):
        FunctionInfoBase.__init__(self)
        self.class_name = class_name
        self.no_return_seek = True
        self.addr = None
    
    def GenerateSignature(self, addr, start_addr):
        self.addr = addr
        print("Generating NoHook signature for address: {}, start address: {}".format(addr, start_addr))
        sig_bytes, mask, length = generate_signature(addr, True, start_addr, True)
        if sig_bytes is not None:
            self.unique = True
            self.no_chain = False
            self.sig_length = length
            self.raw_sig = fmt_hex(sig_bytes, mask)
            return True
        
        sig_bytes, mask, length = generate_signature(addr, False, start_addr, True)
        if sig_bytes is not None:
            self.unique = False
            self.no_chain = False
            self.sig_length = length
            self.raw_sig = fmt_hex(sig_bytes, mask)
            return True
        
        sig_bytes, mask, length = generate_signature(addr, True, currentProgram.getMinAddress(), True)
        if sig_bytes is not None:
            self.unique = True
            self.no_chain = True
            self.sig_length = length
            self.raw_sig = fmt_hex(sig_bytes, mask)
            return True
        
        sig_bytes, mask, length = generate_signature(addr, False, currentProgram.getMinAddress(), True)
        if sig_bytes is not None:
            self.unique = False
            self.no_chain = True
            self.sig_length = length
            self.raw_sig = fmt_hex(sig_bytes, mask)
            return True
        
        return False
    
    def OutputZHLSignature(self):
        # Generate signature string
        sig = ""
        if self.no_return_seek:
            sig += "!"
        if not self.no_chain:
            sig += "."
        sig += self.raw_sig.lower().replace(" ", "")
        
        ret = "\"{}\": ".format(sig)
        if self.unique:
            ret += " // unique sig\n"
        else:
            ret += " // non-unique sig\n"
        
        ret += "noHook __amd64 void {}::__DO_NOT_HOOK(); // {}\n".format(self.class_name, self.addr)
        return ret

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

monitor = ConsoleTaskMonitor()

mem = currentProgram.getMemory()
fm  = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
addr_factory = currentProgram.getAddressFactory()
POINTER_SIZE = currentProgram.getDefaultPointerSize()

MAX_LEN = 512     # maximum bytes to try

def search_pattern(pattern_bytes, mask_bytes, start):
    """
    Search entire binary for a masked byte pattern.
    Return number of matches.
    """
    matches = 0
    
    # Convert to Java byte[]
    j_sig  = jarray.array([b if b < 128 else b-256 for b in pattern_bytes], 'b')
    j_mask = jarray.array([m if m < 128 else m-256 for m in mask_bytes], 'b')

    addr = mem.findBytes(start, j_sig, j_mask, True, monitor)
    while addr is not None:
        matches += 1
        # search again from next byte
        next_addr = addr.addNoWrap(1)
        addr = mem.findBytes(next_addr, j_sig, j_mask, True, monitor)

    return matches

def is_the_first_match(pattern_bytes, mask_bytes, start):
    """
    Check if the first match of a masked byte pattern is at the start address.
    Return True/False.
    """    
    # Convert to Java byte[]
    j_sig  = jarray.array([b if b < 128 else b-256 for b in pattern_bytes], 'b')
    j_mask = jarray.array([m if m < 128 else m-256 for m in mask_bytes], 'b')

    addr = mem.findBytes(start, j_sig, j_mask, True, monitor)
    if addr is None:
        return False

    return addr == start

def to_le_bytes(value, size):
    bytes_out = bytearray(size)
    for i in range(size):
        bytes_out[i] = (value >> (8 * i)) & 0xFF
    return bytes_out


def scalar_byte_length(scalar_obj):
    if hasattr(scalar_obj, "getLength"):
        length = scalar_obj.getLength()
        if length and length > 0:
            if length <= 8:
                return length
            return max(1, (length + 7) // 8)
    if hasattr(scalar_obj, "bitLength"):
        bits = scalar_obj.bitLength()
        if bits and bits > 0:
            return max(1, (bits + 7) // 8)
    return POINTER_SIZE


def find_subarrays(haystack, needle):
    matches = []
    if not needle or len(needle) > len(haystack):
        return matches
    last = len(haystack) - len(needle) + 1
    for i in range(last):
        if haystack[i:i + len(needle)] == needle:
            matches.append(i)
    return matches


def mask_operand_bytes(instr, func_start, wildcard_indices):
    instr_start = instr.getAddress()
    start_offset = instr_start.subtract(func_start)
    instr_len = instr.getLength()
    j_instr_bytes = jarray.zeros(instr_len, 'b')

    try:
        mem.getBytes(instr_start, j_instr_bytes)
    except MemoryAccessException:
        print("  Failed to read bytes at instruction: {}".format(instr_start))
        return

    instr_bytes = [b & 0xFF for b in j_instr_bytes]

    for op_index in range(instr.getNumOperands()):
        op_type = instr.getOperandType(op_index)
        if (op_type & OperandType.ADDRESS) == 0:
            continue

        objects = instr.getOpObjects(op_index)
        for obj in objects:
            candidates = []
            
            if isinstance(obj, Scalar):
                byte_len = scalar_byte_length(obj)
                unsigned_value = obj.getUnsignedValue() if hasattr(obj, "getUnsignedValue") else obj.getValue()
                candidates.append(to_le_bytes(unsigned_value, byte_len))
            
            elif isinstance(obj, Address):
                # Absolute
                if mem.contains(obj):
                    candidates.append(to_le_bytes(obj.getOffset(), POINTER_SIZE))
                
                # Relative
                next_instr_addr = instr.getAddress().add(instr.getLength())
                try:
                    offset = obj.subtract(next_instr_addr)
                    candidates.append(to_le_bytes(offset, 1))
                    candidates.append(to_le_bytes(offset, 4))
                except:
                    pass

            if not candidates:
                continue

            # print("    Wildcarding operand bytes for object: {}".format(obj))
            # print("    Instruction bytes: {}".format(" ".join("{:02X}".format(b) for b in instr_bytes)))

            for value_bytes in candidates:
                # print("    Value bytes: {}".format(" ".join("{:02X}".format(b) for b in value_bytes)))
                matches = find_subarrays(instr_bytes, list(value_bytes))
                # print("    Found {} matches in instruction bytes.".format(len(matches)))
                for match_offset in matches:
                    for i in range(len(value_bytes)):
                        idx = start_offset + match_offset + i
                        # print("    Wildcarding byte at offset: {}".format(idx))
                        wildcard_indices.add(idx)


def wildcard_instruction_addresses(func_start, current_addr, wildcard_indices, processed_instr):
    instr = listing.getInstructionContaining(current_addr)
    if instr is None:
        # print("  No instruction at address: {}".format(current_addr))
        return

    instr_start = instr.getAddress()
    if instr_start in processed_instr:
        return

    processed_instr.add(instr_start)
    mask_operand_bytes(instr, func_start, wildcard_indices)


def find_ret_address(start_addr):
    curr = start_addr
    while True:
        try:
            b = mem.getByte(curr) & 0xFF
            if b == 0xC3 or b == 0xC2:
                return curr
            curr = curr.add(1)
        except:
            return None

def generate_signature(addr, unique, start_addr, backwards=False):
    sig_bytes = []
    mask = []
    processed_instr = set()
    wildcard_indices = set()

    for i in range(MAX_LEN):
        if backwards:
            current_addr = addr.subtract(i)
            if current_addr.compareTo(start_addr) < 0:
                break

            wildcard_instruction_addresses(addr, current_addr, wildcard_indices, processed_instr)

            b = mem.getByte(current_addr)
            sig_bytes.append(b)

            check_sig = sig_bytes[::-1]
            check_mask = []

            for k in range(i + 1):
                offset = k - i
                if offset in wildcard_indices:
                    check_mask.append(0x00)
                else:
                    check_mask.append(0xFF)

            if unique:
                matches = search_pattern(check_sig, check_mask, start_addr)
                if matches == 1:
                    return check_sig, check_mask, i+1
            else:
                if is_the_first_match(check_sig, check_mask, start_addr):
                    return check_sig, check_mask, i+1
        else:
            current_addr = addr.add(i)
            wildcard_instruction_addresses(addr, current_addr, wildcard_indices, processed_instr)

            b = mem.getByte(addr.add(i))

            sig_bytes.append(b)
            
            if i in wildcard_indices:
                mask.append(0x00)
            else:
                mask.append(0xFF)

            if unique:
                # Check uniqueness
                matches = search_pattern(sig_bytes, mask, start_addr)
                # print("  Trying length {}: {} matches".format(i+1, matches))
                if matches == 1:
                    return sig_bytes, mask, i+1
            else:
                if is_the_first_match(sig_bytes, mask, start_addr):
                    return sig_bytes, mask, i+1

    return None, None, None

def fmt_hex(bytes_, mask):
    parts = []
    for b, m in zip(bytes_, mask):
        if m == 0:
            parts.append("??")
        else:
            parts.append("{:02X}".format((b + 256) % 256))
    return " ".join(parts)


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

class_map = {name: [] for name in TARGET_NAMESPACES}

functions_unsorted = fm.getFunctions(True)


for func in functions_unsorted:
    sym = func.getSymbol()
    if sym is None:
        continue

    ns = sym.getParentNamespace()
    if ns is None:
        continue

    if ns.isGlobal():
        continue

    # Extract actual class name
    class_name = ns.getName()
    if class_name not in TARGET_NAMESPACES:
        continue
    
    # if class_name != "Asteroid":
    #     continue
    
    # Exclude thunks
    # 1. Check if function is a pure thunk
    if func.isThunk():
        continue
    # 2. Check for "thunk" in the plate comment (common for adjustor thunks)
    cu = currentProgram.getListing().getCodeUnitAt(func.getEntryPoint())
    plate_comment = cu.getComment(CodeUnit.PLATE_COMMENT) if cu else None
    if plate_comment and "thunk" in plate_comment.lower():
        continue
    
    class_map[class_name].append(FunctionInfo(func, class_name))

for class_name, functions_unsorted in sorted(class_map.items()):
    functions = sorted(functions_unsorted, key=lambda fi: fi.func.getEntryPoint())
    if not functions:
        continue
    
    functions[0].no_chain = True  # First function cannot chain
    for i, func_info in enumerate(functions):
        func = func_info.func
        func_previous = None
        for j in range(i-1, -1, -1):
            if not functions[j].failed:
                func_previous = functions[j]
                break
            
        print("Generating signature for function: {}::{} @ {}".format(class_name, func.getName(), func.getEntryPoint()))
        
        if i > 0 and func.getEntryPoint() < func_previous.ret_address:
            if func.getEntryPoint() < func_previous.func.getEntryPoint().add(func_previous.sig_length):
                # Overlaps with previous function's signature. Skip chaining.
                func_info.no_chain = True
            else:
                func_previous.no_return_seek = True
            
        start_addr = currentProgram.getMinAddress() if func_info.no_chain else func_previous.ret_address

        sig_bytes, mask, length = generate_signature(func.getEntryPoint(), True, start_addr)
        if sig_bytes is None:
            sig_bytes, mask, length = generate_signature(func.getEntryPoint(), False, start_addr)
            if sig_bytes is None:
                func_info.dummy_hook = NoHook(class_name)
                if func_info.dummy_hook.GenerateSignature(func.getEntryPoint().subtract(1), start_addr):
                    sig_bytes, mask, length = generate_signature(func.getEntryPoint(), False, func.getEntryPoint())
                    assert sig_bytes is not None, "Failed to generate signature for function: {}::{}".format(class_name, func.getName())
                else:
                    func_info.failed = True
                    print("  Failed to generate signature for function: {}::{}".format(class_name, func.getName()))
                    continue
            
            func_info.unique = False
        
        func_info.sig_length = length
        
        ret_addr = find_ret_address(func.getEntryPoint().add(length))
        assert ret_addr is not None, "Failed to find RET address for function: {}::{}".format(class_name, func.getName())
        func_info.ret_address = ret_addr
        # print("  RET found at: {}".format(ret_addr))

        pattern = fmt_hex(sig_bytes, mask)
        print("{} @ {} -> {}".format(class_name + "::" + func.getName(), func.getEntryPoint(), pattern))
        func_info.raw_sig = pattern
    
    OUTPUT_DIR = u"ZHL_Signatures_Extracted"
    ensure_dir(OUTPUT_DIR)
    filepath = unicode(os.path.join(OUTPUT_DIR, u"{}.zhl".format(class_name)))
    with open(filepath, "w") as f:
        for func_info in functions:
            sig_output = func_info.OutputZHLSignature()
            f.write(sig_output)
    print("Wrote signatures to: {}".format(filepath))

print("All signatures generated!")