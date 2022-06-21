use std::collections::HashMap;
use crate::opcodes;
use bitflags::bitflags;

#[derive(PartialEq)]
pub enum AddressingMode {
    Immediate,
    ZeroPage,
    ZeroPageX,
    ZeroPageY,
    Absolute,
    AbsoluteX,
    AbsoluteY,
    IndirectX,
    IndirectY,
    NoneAddressing
}

bitflags! {
    pub struct CpuFlags: u8 {
        const CARRY = 0b00000001;
        const ZERO = 0b00000010;
        const INTERRUPT_DISABLE = 0b00000100;
        const DECIMAL_MODE = 0b00001000;
        const BREAK = 0b00010000;
        const BREAK2 = 0b00100000;
        const OVERFLOW = 0b01000000;
        const NEGATIVE = 0b10000000;
    }
}

const STACK: u16 = 0x0100;
const STACK_RESET: u8 = 0xfd;

pub struct CPU {
    pub register_a: u8,
    pub register_x: u8,
    pub register_y: u8,
    pub status: CpuFlags,
    pub stack_pointer: u8,
    pub program_counter: u16,
    memory: [u8; 0xFFFF],
}

impl CPU {
    pub fn new() -> Self {
        CPU {
            register_a: 0,
            register_x: 0,
            register_y: 0,
            status: CpuFlags::from_bits_truncate(0b100100),
            stack_pointer: STACK_RESET,
            program_counter: 0,
            memory: [0; 0xFFFF],
        }
    }

    fn mem_read(&self, addr: u16) -> u8 {
        self.memory[addr as usize]
    }

    fn mem_read_u16(& self, pos: u16) -> u16 {
        let lo = self.mem_read(pos) as u16;
        let hi = self.mem_read(pos + 1) as u16;
        (hi << 8) | (lo as u16)
    }

    fn mem_write(&mut self, addr: u16, data: u8) {
        self.memory[addr as usize] = data;
    }

    fn mem_write_u16(&mut self, pos: u16, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.mem_write(pos, lo);
        self.mem_write(pos + 1, hi);
    }

    fn stack_push(&mut self, data: u8) {
        self.mem_write((STACK as u16) + self.stack_pointer as u16, data);
        self.stack_pointer = self.stack_pointer.wrapping_sub(1);
    }

    fn stack_pop(&mut self) -> u8 {
        self.stack_pointer = self.stack_pointer.wrapping_add(1);
        self.mem_read((STACK as u16) + self.stack_pointer as u16)
    }

    fn stack_push_u16(&mut self, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xFF) as u8;
        self.stack_push(hi);
        self.stack_push(lo);
    }

    fn stack_pop_u16(&mut self) -> u16 {
        let lo = self.stack_pop() as u16;
        let hi = self.stack_pop() as u16;
        hi << 8 | lo
    }

    pub fn load(&mut self, program: Vec<u8>) {
        self.memory[0x8000..(0x8000 + program.len())].copy_from_slice(&program[..]);
        self.mem_write_u16(0xFFFC, 0x8000);
    }

    pub fn reset(&mut self) {
        self.register_a = 0;
        self.register_x = 0;
        self.register_y = 0;
        self.status = CpuFlags::from_bits_truncate(0b100100);
        self.stack_pointer = STACK_RESET;
        self.program_counter = self.mem_read_u16(0xFFFC);
    }

    fn get_operand_address(&self, mode: &AddressingMode) -> u16 {
        match mode {
            AddressingMode::Immediate => self.program_counter,
            AddressingMode::ZeroPage => self.mem_read(self.program_counter) as u16,
            AddressingMode::ZeroPageX => {
                let pos = self.mem_read(self.program_counter);
                let addr = pos.wrapping_add(self.register_x) as u16;
                addr
            }
            AddressingMode::ZeroPageY => {
                let pos = self.mem_read(self.program_counter);
                let addr = pos.wrapping_add(self.register_y) as u16;
                addr
            }
            AddressingMode::Absolute => self.mem_read_u16(self.program_counter),
            AddressingMode::AbsoluteX => {
                let base = self.mem_read_u16(self.program_counter);
                let addr = base.wrapping_add(self.register_x as u16);
                addr
            }
            AddressingMode::AbsoluteY => {
                let base = self.mem_read_u16(self.program_counter);
                let addr = base.wrapping_add(self.register_y as u16);
                addr
            }
            AddressingMode::IndirectX => {
                let base = self.mem_read(self.program_counter);

                let ptr: u8 = (base as u8).wrapping_add(self.register_x);
                let lo = self.mem_read(ptr as u16);
                let hi = self.mem_read(ptr.wrapping_add(1) as u16);
                (hi as u16) << 8 | (lo as u16)
            }
            AddressingMode::IndirectY => {
                let base = self.mem_read(self.program_counter);
                let lo = self.mem_read(base as u16);
                let hi = self.mem_read((base as u8).wrapping_add(1) as u16);
                let deref_base = (hi as u16) << 8 | (lo as u16);
                let deref = deref_base.wrapping_add(self.register_y as u16);
                deref
            }
            AddressingMode::NoneAddressing => {
                panic!("Addressing mode not supported by the NES!");
            }
        }
    }

    fn update_zero_and_negative_flags(&mut self, result: u8) {
        if result == 0 {
            self.status.insert(CpuFlags::ZERO);
        } else {
            self.status.remove(CpuFlags::ZERO);
        }

        if result & 0b1000000 != 0 {
            self.status.insert(CpuFlags::NEGATIVE);
        } else {
            self.status.remove(CpuFlags::NEGATIVE);
        }
    }

    fn set_register_a(&mut self, value: u8) {
        self.register_a = value;
        self.update_zero_and_negative_flags(self.register_a);
    }

    fn add_to_register_a(&mut self, value: u8) {
        let mut sum = self.register_a as u16 + value as u16;
        if self.status.contains(CpuFlags::CARRY) {
            sum += 1 as u16;
        }

        if sum > 0xFF {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }

        let result = sum as u8;
        if (value ^ result) & (result ^ self.register_a) & 0x80 != 0 {
            self.status.insert(CpuFlags::OVERFLOW);
        } else {
            self.status.remove(CpuFlags::OVERFLOW);
        }

        self.set_register_a(result);
    }

    fn adc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);

        self.add_to_register_a(value);
    }

    fn and(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);

        self.set_register_a(value & self.register_a)
    }

    fn asl(&mut self, mode: &AddressingMode) {
        if mode == &AddressingMode::NoneAddressing {
            if self.register_a >> 7 == 1 {
                self.status.insert(CpuFlags::CARRY);
            } else {
                self.status.remove(CpuFlags::CARRY);
            }

            self.set_register_a(self.register_a << 1);
        } else {
            let addr = self.get_operand_address(&mode);
            let mut value = self.mem_read(addr);

            if value >> 7 == 1 {
                self.status.insert(CpuFlags::CARRY);
            } else {
                self.status.remove(CpuFlags::CARRY);
            }

            value = value << 1;
            self.mem_write(addr, value);
            self.update_zero_and_negative_flags(value);
        }

    }

    fn bit(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);

        if self.register_a & value == 0 {
            self.status.insert(CpuFlags::ZERO);
        } else {
            self.status.remove(CpuFlags::ZERO);
        }

        self.status.set(CpuFlags::NEGATIVE, value & 0b10000000 > 0);
        self.status.set(CpuFlags::OVERFLOW, value & 0b01000000 > 0);
    }

    fn branch(&mut self, condition: bool) {
        if condition {
            let jump_amt: i8 = self.mem_read(self.program_counter) as i8;
            let jump_addr = self.program_counter.wrapping_add(1).wrapping_add(jump_amt as u16);

            self.program_counter = jump_addr;
        }
    }

    fn compare(&mut self, mode: &AddressingMode, register: u8) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);

        if value <= register {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }

        self.update_zero_and_negative_flags(register.wrapping_sub(value));
    }

    fn dec(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let mut value = self.mem_read(addr);

        value = value.wrapping_sub(1);
        self.mem_write(addr, value);
        self.update_zero_and_negative_flags(value);
    }

    fn eor(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);
        self.set_register_a(value ^ self.register_a);
    }

    fn inc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let mut value = self.mem_read(addr);

        value = value.wrapping_add(1);
        self.mem_write(addr, value);
        self.update_zero_and_negative_flags(value);
    }

    fn jmp_absolute(&mut self) {
        self.program_counter = self.mem_read_u16(self.program_counter);
    }

    fn jmp_indirect(&mut self) {
        let addr_ref = self.mem_read_u16(self.program_counter);
        let addr;
        if addr_ref & 0x00FF == 0x00FF {
            let lo = self.mem_read(addr_ref);
            let hi = self.mem_read(addr_ref & 0xFF00);
            addr = (hi as u16) << 8 | (lo as u16);
        } else {
            addr = self.mem_read_u16(addr_ref);
        }
        self.program_counter = addr;
    }

    fn jsr(&mut self) {
        self.stack_push_u16(self.program_counter + 1);
        self.program_counter = self.mem_read_u16(self.program_counter);
    }

    fn lda(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);
        self.set_register_a(value);
    }

    fn ldx(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);
        self.register_x = value;
        self.update_zero_and_negative_flags(value);
    }

    fn ldy(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);
        self.register_y = value;
        self.update_zero_and_negative_flags(value);
    }

    fn lsr(&mut self, mode: &AddressingMode) {
        if mode == &AddressingMode::NoneAddressing {
            if self.register_a & 1 == 1 {
                self.status.insert(CpuFlags::CARRY);
            } else {
                self.status.remove(CpuFlags::CARRY);
            }

            self.set_register_a(self.register_a >> 1);
        } else {
            let addr = self.get_operand_address(&mode);
            let mut value = self.mem_read(addr);

            if value & 1 == 1 {
                self.status.insert(CpuFlags::CARRY);
            } else {
                self.status.remove(CpuFlags::CARRY);
            }

            value = value >> 1;
            self.mem_write(addr, value);
            self.update_zero_and_negative_flags(value);
        }
    }

    fn ora(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);
        self.set_register_a(value | self.register_a);
    }

    fn tax(&mut self) {
        self.register_x = self.register_a;
        self.update_zero_and_negative_flags(self.register_x);
    }

    fn txa(&mut self) {
        self.set_register_a(self.register_x);
    }

    fn dex(&mut self) {
        self.register_x = self.register_x.wrapping_sub(1);
        self.update_zero_and_negative_flags(self.register_x);
    }

    fn inx(&mut self) {
        self.register_x = self.register_x.wrapping_add(1);
        self.update_zero_and_negative_flags(self.register_x);
    }

    fn tay(&mut self) {
        self.register_y = self.register_a;
        self.update_zero_and_negative_flags(self.register_y);
    }

    fn tya(&mut self) {
        self.set_register_a(self.register_y);
    }

    fn dey(&mut self) {
        self.register_y = self.register_y.wrapping_sub(1);
        self.update_zero_and_negative_flags(self.register_y);
    }

    fn iny(&mut self) {
        self.register_y = self.register_y.wrapping_add(1);
        self.update_zero_and_negative_flags(self.register_y);
    }

    fn rol(&mut self, mode: &AddressingMode) {
        let carry = self.status.contains(CpuFlags::CARRY);
        let mut value;
        let mut addr = 0;
        if mode == &AddressingMode::NoneAddressing {
            value = self.register_a;
        } else {
            addr = self.get_operand_address(&mode);
            value = self.mem_read(addr);
        }

        if value >> 7 == 1 {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }

        value = value << 1;
        if carry {
            value = value | 1;
        }

        if mode == &AddressingMode::NoneAddressing {
            self.set_register_a(value);
        } else {
            self.mem_write(addr, value);
            self.update_zero_and_negative_flags(value);
        }
    }

    fn ror(&mut self, mode: &AddressingMode) {
        let carry = self.status.contains(CpuFlags::CARRY);
        let mut value;
        let mut addr = 0;
        if mode == &AddressingMode::NoneAddressing {
            value = self.register_a;
        } else {
            addr = self.get_operand_address(&mode);
            value = self.mem_read(addr);
        }

        if value & 1 == 1 {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }

        value = value >> 1;
        if carry {
            value = value | 0b10000000;
        }

        if mode == &AddressingMode::NoneAddressing {
            self.set_register_a(value);
        } else {
            self.mem_write(addr, value);
            self.update_zero_and_negative_flags(value);
        }
    }

    fn rti(&mut self) {
        self.status.bits = self.stack_pop();
        self.status.remove(CpuFlags::BREAK);
        self.status.insert(CpuFlags::BREAK2);
        self.program_counter = self.stack_pop_u16();
    }

    fn rts(&mut self) {
        self.program_counter = self.stack_pop_u16() + 1;
    }

    fn sbc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);

        self.add_to_register_a(((value as i8).wrapping_neg().wrapping_sub(1)) as u8);
    }

    fn sta(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        self.mem_write(addr, self.register_a);
    }

    fn txs(&mut self) {
        self.stack_pointer = self.register_x;
    }

    fn tsx(&mut self) {
        self.register_x = self.stack_pointer;
        self.update_zero_and_negative_flags(self.register_x);
    }

    fn pha(&mut self) {
        self.stack_push(self.register_a);
    }

    fn pla(&mut self) {
        let value = self.stack_pop();
        self.set_register_a(value);
    }

    fn php(&mut self) {
        let mut flags = self.status.clone();
        flags.insert(CpuFlags::BREAK);
        flags.insert(CpuFlags::BREAK2);
        self.stack_push(flags.bits());
    }

    fn plp(&mut self) {
        self.status.bits = self.stack_pop();
        self.status.remove(CpuFlags::BREAK);
        self.status.insert(CpuFlags::BREAK2);
    }

    fn stx(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.register_x);
    }

    fn sty(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.register_y)
    }

    pub fn run(&mut self) {
        let ref opcodes: HashMap<u8, &'static opcodes::OpCode> = *opcodes::OPCODES_MAP;

        loop {
            let code = self.mem_read(self.program_counter);
            self.program_counter += 1;
            let program_counter_state = self.program_counter;

            let opcode = opcodes.get(&code).expect(&format!("Invalid opcode {:x}", code));

            match code {
                // ADC
                0x69 | 0x65 | 0x75 | 0x6D | 0x7D | 0x79 | 0x61 | 0x71 => {
                    self.adc(&opcode.mode);
                }
                // AND
                0x29 | 0x25 | 0x35 | 0x2D | 0x3D | 0x39 | 0x21 | 0x31 => {
                    self.and(&opcode.mode);
                }
                // ASL
                0x0A | 0x06 | 0x16 | 0x0E | 0x1E => {
                    self.asl(&opcode.mode);
                }
                // BIT
                0x24 | 0x2C => {
                    self.bit(&opcode.mode);
                }
                // BPL
                0x10 => {
                    self.branch(!self.status.contains(CpuFlags::NEGATIVE));
                },
                // BMI
                0x30 => {
                    self.branch(self.status.contains(CpuFlags::NEGATIVE));
                },
                // BVC
                0x50 => {
                    self.branch(!self.status.contains(CpuFlags::OVERFLOW));
                },
                // BVS
                0x70 => {
                    self.branch(self.status.contains(CpuFlags::OVERFLOW));
                },
                // BCC
                0x90 => {
                    self.branch(!self.status.contains(CpuFlags::CARRY));
                },
                // BCS
                0xB0 => {
                    self.branch(self.status.contains(CpuFlags::CARRY));
                },
                // BNE
                0xD0 => {
                    self.branch(!self.status.contains(CpuFlags::ZERO));
                },
                // BEQ
                0xF0 => {
                    self.branch(self.status.contains(CpuFlags::ZERO));
                },
                // BRK
                0x00 => return,
                // CMP
                0xC9 | 0xC5 | 0xD5 | 0xCD | 0xDD | 0xD9 | 0xC1 | 0xD1 => {
                    self.compare(&opcode.mode, self.register_a);
                }
                // CPX
                0xE0 | 0xE4 | 0xEC => {
                    self.compare(&opcode.mode, self.register_x);
                }
                // CPY
                0xC0 | 0xC4 | 0xCC => {
                    self.compare(&opcode.mode, self.register_y);
                }
                // DEC
                0xC6 | 0xD6 | 0xCE | 0xDE => {
                    self.dec(&opcode.mode);
                }
                // EOR
                0x49 | 0x45 | 0x55 | 0x4D | 0x5D | 0x59 | 0x41 | 0x51 => {
                    self.eor(&opcode.mode);
                }
                // CLC
                0x18 => {
                    self.status.remove(CpuFlags::CARRY);
                },
                // SEC
                0x38 => {
                    self.status.insert(CpuFlags::CARRY);
                },
                // CLI
                0x58 => {
                    self.status.remove(CpuFlags::INTERRUPT_DISABLE);
                },
                // SEI
                0x78 => {
                    self.status.insert(CpuFlags::INTERRUPT_DISABLE);
                },
                // CLV
                0xB8 => {
                    self.status.remove(CpuFlags::OVERFLOW);
                },
                // CLD
                0xD8 => {
                    self.status.remove(CpuFlags::DECIMAL_MODE);
                },
                // SED
                0xF8 => {
                    self.status.insert(CpuFlags::DECIMAL_MODE);
                },
                // INC
                0xE6 | 0xF6 | 0xEE | 0xFE => {
                    self.inc(&opcode.mode);
                }
                // JMP
                0x4C => {
                    self.jmp_absolute();
                }
                0x6C => {
                    self.jmp_indirect();
                }
                // JSR
                0x20 => {
                    self.jsr();
                },
                // LDA
                0xA9 | 0xA5 | 0xB5 | 0xAD | 0xBD | 0xB9 | 0xA1 | 0xB1 => {
                    self.lda(&opcode.mode);
                }
                // LDX
                0xA2 | 0xA6 | 0xB6 | 0xAE | 0xBE => {
                    self.ldx(&opcode.mode);
                }
                // LDY
                0xA0 | 0xA4 | 0xB4 | 0xAC | 0xBC => {
                    self.ldy(&opcode.mode);
                }
                // LSR
                0x4A | 0x46 | 0x56 | 0x4E | 0x5E => {
                    self.lsr(&opcode.mode);
                }
                // NOP
                0xEA => {},
                // ORA
                0x09 | 0x05 | 0x15 | 0x0D | 0x1D | 0x19 | 0x01 | 0x11 => {
                    self.ora(&opcode.mode);
                }
                // TAX
                0xAA => {
                    self.tax();
                },
                // TXA
                0x8A => {
                    self.txa();
                },
                // DEX
                0xCA => {
                    self.dex();
                },
                // INX
                0xE8 => {
                    self.inx();
                },
                // TAY
                0xA8 => {
                    self.tay();
                },
                // TYA
                0x98 => {
                    self.tya();
                }
                // DEY
                0x88 => {
                    self.dey();
                },
                // INY
                0xC8 => {
                    self.iny();
                },
                // ROL
                0x2A | 0x26 | 0x36 | 0x2E | 0x3E => {
                    self.rol(&opcode.mode);
                }
                // ROR
                0x6A | 0x66 | 0x76 | 0x6E | 0x7E => {
                    self.ror(&opcode.mode);
                }
                // RTI
                0x40 => {
                    self.rti();
                },
                // RTS
                0x60 => {
                    self.rts();
                },
                // SBC
                0xE9 | 0xE5 | 0xF5 | 0xED | 0xFD | 0xF9 | 0xE1 | 0xF1 => {
                    self.sbc(&opcode.mode);
                }
                // STA
                0x85 | 0x95 | 0x8D | 0x9D | 0x99 | 0x81 | 0x91 => {
                    self.sta(&opcode.mode);
                }
                // TXS
                0x9A => {
                    self.txs();
                },
                // TSX
                0xBA => {
                    self.tsx();
                },
                // PHA
                0x48 => {
                    self.pha();
                },
                // PLA
                0x68 => {
                    self.pla();
                },
                // PHP
                0x08 => {
                    self.php();
                },
                // PLP
                0x28 => {
                    self.plp();
                },
                // STX
                0x86 | 0x96 | 0x8E => {
                    self.stx(&opcode.mode);
                }
                // STY
                0x84 | 0x94 | 0x8C => {
                    self.sty(&opcode.mode);
                }
                _ => {}
            }

            if program_counter_state == self.program_counter {
                self.program_counter += (opcode.len - 1) as u16;
            }
        }
    }

    pub fn load_and_run(&mut self, program: Vec<u8>) {
        self.load(program);
        self.reset();
        self.run();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_cpu() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xA2, 0xFF, 0xE8, 0x00]);
        assert_eq!(cpu.register_x, 0);
    }
}