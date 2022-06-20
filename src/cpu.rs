use std::collections::HashMap;
use crate::opcodes;

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

pub struct CPU {
    pub register_a: u8,
    pub register_x: u8,
    pub register_y: u8,
    pub status: u8,
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
            status: 0,
            stack_pointer: 0,
            program_counter: 0,
            memory: [u8; 0xFFFF],
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

    pub fn load(&mut self, program: Vec<u8>) {
        self.memory[0x8000..(0x8000 + program.len())].copy_from_slice(&program[..]);
        self.mem_write_u16(0xFFFC, 0x8000);
    }

    pub fn reset(&mut self) {
        self.register_a = 0;
        self.register_x = 0;
        self.register_y = 0;
        self.status = 0;
        self.stack_pointer = 0;
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

    fn ora(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);

        self.register_a = self.register_a | value;
        self.update_zero_and_negative_flags(self.register_a);
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

                }
                // AND
                0x29 | 0x25 | 0x35 | 0x2D | 0x3D | 0x39 | 0x21 | 0x31 => {

                }
                // ASL
                0x0A | 0x06 | 0x16 | 0x0E | 0x1E => {

                }
                // BIT
                0x24 | 0x2C => {

                }
                // BPL
                0x10 => return,
                // BMI
                0x30 => return,
                // BVC
                0x50 => return,
                // BVS
                0x70 => return,
                // BCC
                0x90 => return,
                // BCS
                0xB0 => return,
                // BNE
                0xD0 => return,
                // BEQ
                0xF0 => return,
                // BRK
                0x00 => return,
                // CMP
                0xC9 | 0xC5 | 0xD5 | 0xCD | 0xDD | 0xD9 | 0xC1 | 0xD1 => {

                }
                // CPX
                0xE0 | 0xE4 | 0xEC => {

                }
                // CPY
                0xC0 | 0xC4 | 0xCC => {

                }
                // DEC
                0xC6 | 0xD6 | 0xCE | 0xDE => {

                }
                // EOR
                0x49 | 0x45 | 0x55 | 0x4D | 0x5D | 0x59 | 0x41 | 0x51 => {

                }
                // CLC
                0x18 => return,
                // SEC
                0x38 => return,
                // CLI
                0x58 => return,
                // SEI
                0x78 => return,
                // CLV
                0xB8 => return,
                // CLD
                0xD8 => return,
                // SED
                0xF8 => return,
                // INC
                0xE6 | 0xF6 | 0xEE | 0xFE => {

                }
                // JMP
                0x4C | 0x6C => {

                }
                // JSR
                0x20 => return,
                // LDA
                0xA9 | 0xA5 | 0xB5 | 0xAD | 0xBD | 0xB9 | 0xA1 | 0xB1 => {

                }
                // LDX
                0xA2 | 0xA6 | 0xB6 | 0xAE | 0xBE => {

                }
                // LDY
                0xA0 | 0xA4 | 0xB4 | 0xAC | 0xBC => {

                }
                // LSR
                0x4A | 0x46 | 0x56 | 0x4E | 0x5E => {

                }
                // NOP
                0xEA => return,
                // ORA
                0x09 | 0x05 | 0x15 | 0x0D | 0x1D | 0x19 | 0x01 | 0x11 => {

                }
                // TAX
                0xAA => return,
                // TXA
                0x8A => return,
                // DEX
                0xCA => return,
                // INX
                0xE8 => return,
                // TAY
                0xA8 => return,
                // TYA
                0x98 => return,
                // DEY
                0x88 => return,
                // INY
                0xC8 => return,
                // ROL
                0x2A | 0x26 | 0x36 | 0x2E | 0x3E => {

                }
                // ROR
                0x6A | 0x66 | 0x76 | 0x6E | 0x7E => {

                }
                // RTI
                0x40 => return,
                // RTS
                0x60 => return,
                // SBC
                0xE9 | 0xE5 | 0xF5 | 0xED | 0xFD | 0xF9 | 0xE1 | 0xF1 => {

                }
                // STA
                0x85 | 0x95 | 0x8D | 0x9D | 0x99 | 0x81 | 0x91 => {

                }
                // TXS
                0x9A => return,
                // TSX
                0xBA => return,
                // PHA
                0x48 => return,
                // PLA
                0x68 => return,
                // PHP
                0x08 => return,
                // PLP
                0x28 => return,
                // STX
                0x86 | 0x96 | 0x8E => {

                }
                // STY
                0x84 | 0x94 | 0x8C => {

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