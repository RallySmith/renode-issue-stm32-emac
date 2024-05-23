// Derived from 1.14.0 SynopsysEthernetMAC.cs
// Further modified from F2 variant to STM32H7 (RM0468 Rev3) MSv40388V8
//
// Fix to ignore ETH_DMA0MR:FTF
// Remove packetSent to allow transmission
// Add TransmitStatus interrupt state (from git head)
// Add CRC and checksum update (from git head)
// Add IPv6 to supportedEthernetChecksums and supportedIPChecksums
// Add MAC[123] functionality and match against destinationMac
// Fix dmaTransmitDescriptorListBegin setting
// Fix dmaReceiveDescriptorsListAddress setting
//
// Modifications Copyright (c) 2023-2024 eCosCentric Ltd
// Original assignment:
//
// Copyright (c) 2010-2023 Antmicro
// Copyright (c) 2011-2015 Realtime Embedded
//
// This file is licensed under the MIT License.
// Full license text is available in 'licenses/MIT.txt'.
//
using System;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Utilities;
using System.Collections.Generic;
using Antmicro.Renode.Network;

namespace Antmicro.Renode.Peripherals.Network
{
    //TODO: Might be Word/BytePeripheral as well
    public sealed class STM32H7_EthernetMAC : NetworkWithPHY, IDoubleWordPeripheral, IMACInterface, IKnownSize
    {
        public STM32H7_EthernetMAC(Machine machine) : base(machine)
        {
            MAC = EmulationManager.Instance.CurrentEmulation.MACRepository.GenerateUniqueMAC();
            MAC1 = new MACAddress(0xFFFFFFFFFFFF);
            MAC2 = new MACAddress(0xFFFFFFFFFFFF);
            MAC3 = new MACAddress(0xFFFFFFFFFFFF);
            IRQ = new GPIO();
            Reset();
        }

        public override void Reset()
        {
            macConfiguration = 0x0000000;
            macHashTableHigh = 0x00000000;
            macHashTableLow = 0x00000000;
            macFrameFilter = 0x00000000;
            macMiiAddress = 0x00000000;
            macMiiData = 0x0000;
            dmaMode = 0x00000000;
            dmaReceiveDescriptorListAddress = 0x00000000;
            dmaReceiveDescriptorListAddressBegin = 0x00000000;
            dmaReceiveDescriptorEndOfRing = 0x00000000;
            dmaTransmitDescriptorListAddress = 0x00000000;
            dmaTransmitDescriptorListAddressBegin = 0x00000000;
            dmaTransmitDescriptorEndOfRing = 0x00000000;
            dmaTransmitControl = 0x00000000;
            dmaInterruptEnable = 0x00000000;
            dmaReceiveControl = 0x00000000;
            dmaMissedFrameCount = 0;
            dmaMissedFrameOverflow = false;

            dmaTransmitRingLength = 1;
            dmaReceiveRingLength = 1;
            dmaAltReceiveBufferSize = 0;

            dmaReceiveBufferSize = 0;

            mtlReceiveQueueOpMode = 0x00700000;
            // RQS=7 indicates RX FIFO size of (8 * 256) == 2K
        }

        public uint ReadDoubleWord(long offset)
        {
            uint value = 0x00000000;
            switch((Registers)offset)
            {
            case Registers.MACConfiguration:
                value = macConfiguration;
                break;
            case Registers.MACHashHigh:
                value = macHashTableHigh;
                break;
            case Registers.MACHashLow:
                value = macHashTableLow;
                break;
            case Registers.MACFrameFilter:
                value = macFrameFilter;
                break;
            case Registers.MACMIIAddress:
                value = macMiiAddress;
                break;
            case Registers.MACMIIData:
                value = macMiiData;
                break;
            case Registers.MACAddress0High:
                // AE always 1
                value = (1u << 31) | (uint)((MAC.F << 8) | MAC.E);
                break;
            case Registers.MACAddress0Low:
                value = (uint)((MAC.D << 24) | (MAC.C << 16) | (MAC.B << 8) | MAC.A);
                break;
            case Registers.MACAddress1High:
                value = (MAC1_AE ? (1u << 31) : 0) | (MAC1_SA ? (1u << 30) : 0) | (uint)((MAC1.F << 8) | MAC1.E);
                break;
            case Registers.MACAddress1Low:
                value = (uint)((MAC1.D << 24) | (MAC1.C << 16) | (MAC1.B << 8) | MAC1.A);
                break;
            case Registers.MACAddress2High:
                value = (MAC2_AE ? (1u << 31) : 0) | (MAC2_SA ? (1u << 30) : 0) | (uint)((MAC2.F << 8) | MAC2.E);
                break;
            case Registers.MACAddress2Low:
                value = (uint)((MAC2.D << 24) | (MAC2.C << 16) | (MAC2.B << 8) | MAC2.A);
                break;
            case Registers.MACAddress3High:
                value = (MAC3_AE ? (1u << 31) : 0) | (MAC3_SA ? (1u << 30) : 0) | (uint)((MAC3.F << 8) | MAC3.E);
                break;
            case Registers.MACAddress3Low:
                value = (uint)((MAC3.D << 24) | (MAC3.C << 16) | (MAC3.B << 8) | MAC3.A);
                break;
            case Registers.DMAMode:
                value = dmaMode;
                break;
            case Registers.DMAReceiveDescriptorListAddress:
                value = dmaReceiveDescriptorListAddress;
                break;
            case Registers.DMATransmitDescriptorListAddress:
                value = dmaTransmitDescriptorListAddress;
                break;
            case Registers.DMATransmitTailPointer:
                value = dmaTransmitTailPointer;
                break;
            case Registers.DMAReceiveTailPointer:
                value = dmaReceiveTailPointer;
                break;
            case Registers.DMAStatusRegister:
                if((dmaStatus & ((1u << 11) | (1u << 6) | (1u << 2) | 1u)) != 0)
                {
                    dmaStatus |= 1u << 15; // NIS (Normal Interrupt Summary)
                }
                value = dmaStatus;
                break;
            case Registers.DMAInterruptEnable:
                value = dmaInterruptEnable;
                break;
            case Registers.DMATransmitControl:
                value = dmaTransmitControl;
                break;
            case Registers.DMAReceiveControl:
                value = dmaReceiveControl;
                break;
            case Registers.DMATransmitRingLength:
                value = (dmaTransmitRingLength - 1);
                break;
            case Registers.DMAReceiveRingLength:
                value = ((dmaAltReceiveBufferSize << 16) | (dmaReceiveRingLength - 1));
                break;
            case Registers.DMAMissedFrameCount:
                value = (dmaMissedFrameCount | (dmaMissedFrameOverflow ? (1u << 15) : 0));
                dmaMissedFrameCount = 0;
                dmaMissedFrameOverflow = false;
                break;
            case Registers.MTLReceiveQueueOperatingMode:
                value = mtlReceiveQueueOpMode;
                break;
            default:
                this.LogUnhandledRead(offset);
                return 0;
            }
            this.NoisyLog("Read {0} value 0x{1:X}", (Registers)offset, value);
            return value;
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            this.NoisyLog("Write {0} value 0x{1:X}", (Registers)offset, value);
            switch((Registers)offset)
            {
            case Registers.MACConfiguration:
                macConfiguration = value;
                crcStrippingForTypeFrames = (macConfiguration & (1u << 21)) != 0; // CSTF
                automaticPadCRCStripping = (macConfiguration & (1u << 20)) != 0; // ACS
                break;
            case Registers.MACHashHigh:
                macHashTableHigh = value;
                break;
            case Registers.MACHashLow:
                macHashTableLow = value;
                break;
            case Registers.MACFrameFilter:
                macFrameFilter = value;
                break;
            case Registers.MACMIIAddress:
                macMiiAddress = value;
                var busyClear = (value & 0x1) != 0;
                if(busyClear)
                {
                    macMiiAddress = macMiiAddress & ~0x1u;
                }
                var phyId = (value >> 21) & 0x1F;
                if(!TryGetPhy<ushort>(phyId, out var phy))
                {
                    this.Log(LogLevel.Warning, "Access to unknown phy {0}", phyId);
                    break;
                }
                if((value & (1u << 1)) != 0)
                {
                    this.Log(LogLevel.Warning, "Clause 45 PHY not supported: phy {0}", phyId);
                    break;
                }
                var register = (ushort)((value >> 16) & 0x1F);
                // GOC
                //  0 = reserved
                //  1 = write
                //  2 = post read increment address for Clause 45 PHY
                //  3 = read
                var isRead = ((value >> 2) & 0x3) == 3;
                if(isRead)
                {
                    macMiiData = phy.Read(register);
                }
                else
                {
                    phy.Write(register, macMiiData);
                }
                break;
            case Registers.MACMIIData:
                if(0 != (value & 0xFFFF0000))
                {
                    this.Log(LogLevel.Warning, "Clause 45 Register Address not supported");
                }
                macMiiData = (ushort)value;
                break;
            case Registers.MACAddress0High:
                // NOTE: bit 31 (AE) always HIGH
                MAC = MAC.WithNewOctets(f: (byte)(value >> 8), e: (byte)value);
                break;
            case Registers.MACAddress0Low:
                MAC = MAC.WithNewOctets(d: (byte)(value >> 24), c: (byte)(value >> 16), b: (byte)(value >> 8), a: (byte)value);
                break;
            case Registers.MACAddress1High:
                MAC1_AE = (value & (1u << 31)) != 0; // AddressEnable for perfect filtering
                MAC1_SA = (value & (1u << 30)) != 0; // SourceAddress (or DestinationAddress)
                MAC1_MBC = (byte)((value >> 24) & 0x3F); // MaskByteControl
                MAC1 = MAC1.WithNewOctets(f: (byte)(value >> 8), e: (byte)value);
                break;
            case Registers.MACAddress2High:
                MAC2_AE = (value & (1u << 31)) != 0;
                MAC2_SA = (value & (1u << 30)) != 0;
                MAC2_MBC = (byte)((value >> 24) & 0x3F);
                MAC2 = MAC2.WithNewOctets(f: (byte)(value >> 8), e: (byte)value);
                break;
            case Registers.MACAddress3High:
                MAC3_AE = (value & (1u << 31)) != 0;
                MAC3_SA = (value & (1u << 30)) != 0;
                MAC3_MBC = (byte)((value >> 24) & 0x3F);
                MAC3 = MAC3.WithNewOctets(f: (byte)(value >> 8), e: (byte)value);
                break;
            case Registers.MACAddress1Low:
                MAC1 = MAC1.WithNewOctets(d: (byte)(value >> 24), c: (byte)(value >> 16), b: (byte)(value >> 8), a: (byte)value);
                break;
            case Registers.MACAddress2Low:
                MAC2 = MAC2.WithNewOctets(d: (byte)(value >> 24), c: (byte)(value >> 16), b: (byte)(value >> 8), a: (byte)value);
                break;
            case Registers.MACAddress3Low:
                MAC3 = MAC3.WithNewOctets(d: (byte)(value >> 24), c: (byte)(value >> 16), b: (byte)(value >> 8), a: (byte)value);
                break;
            case Registers.DMAMode:
                dmaMode = value & ~0x1u;
                if((value & 0x1) != 0)
                {
                    Reset();
                }
                break;
            case Registers.DMATransmitTailPointer:
                dmaTransmitTailPointer = value;
                // On write code will attempt to transmit all packets
                // from head->tail (but based on tx ring length) when
                // StartStopTransmission is set (1):
                if ((dmaTransmitControl & StartStopTransmission) != 0)
                {
                    this.Log(LogLevel.Debug, "WriteDoubleWord: DMATransmitTailPointer: Starting transmission");
                    SendFrames();
                }
                break;
            case Registers.DMAReceiveTailPointer:
                dmaReceiveTailPointer = value;
                // On write code will attempt to receive packets from
                // head->tail (but based on tx ring length) when
                // StartStopReceive is set (1):
                if ((dmaReceiveControl & StartStopReceive) != 0)
                {
                    this.Log(LogLevel.Debug, "WriteDoubleWord: DMAReceiveTailPointer: Starting reception");
                    // CONSIDER: Currently a NOP. Real H/W would POLL
                    // next RX descriptor (ETH_DMACRXDLAR) or the
                    // position the DMA previously stopped.
                }
                break;
            case Registers.DMAReceiveDescriptorListAddress:
                // TODO: writing only allowed when RX stopped (ETH_DMACRXCR:SR==0) // TODO: must be written before START command given
                dmaReceiveDescriptorListAddress = value & ~3u;
                dmaReceiveDescriptorListAddressBegin = dmaReceiveDescriptorListAddress;
                dmaReceiveDescriptorEndOfRing = (dmaReceiveDescriptorListAddressBegin + (dmaReceiveRingLength * 16));
                this.Log(LogLevel.Info, "Setting RDLA to 0x{0:X} dmaReceiveDescriptorEndOfRing 0x{1:X}", dmaReceiveDescriptorListAddress, dmaReceiveDescriptorEndOfRing);
                break;
            case Registers.DMATransmitDescriptorListAddress:
                // TODO: can be written only when ETH_DMACTXCR:ST==0 // when ST==1 and this reg not changed then DMA should continue from previous stopped address
                dmaTransmitDescriptorListAddress = value & ~3u;
                dmaTransmitDescriptorListAddressBegin = dmaTransmitDescriptorListAddress;
                dmaTransmitDescriptorEndOfRing = (dmaTransmitDescriptorListAddressBegin + (dmaTransmitRingLength * 16));
                this.Log(LogLevel.Info, "Setting TDLA to 0x{0:X} dmaTransmitDescriptorEndOfRing 0x{1:X}", dmaTransmitDescriptorListAddress, dmaTransmitDescriptorEndOfRing);
                break;
            case Registers.DMAStatusRegister:
                // Not all bits are W1C: bits [21:16] RO and bit [9] RW
                dmaStatus &= ~(value & 0x0000FDC7); // write 1 to clear bits
                // [15] NIS is "sticky" and must be manually cleared (RC_W1 "Read and W1C - writing 0 has no effect")
                if((value & NormalInterruptSummary) != 0)
                {
                    this.Log(LogLevel.Debug, "WriteDoubleWord:DMAStatusRegister: NIS W1C: IRQ.Unset and TryDequeueFrame");
                    IRQ.Unset();
                    TryDequeueFrame();
                }
                this.Log(LogLevel.Debug, "WriteDoubleWord: DMAStatusRegister: dmaStatus now 0x{0:X}", dmaStatus);
                break;
            case Registers.DMATransmitControl:
                dmaTransmitControl = (value & 0x003F1011);
                // [21:16] TXPBL : ignored
                // [12] TSE (TCP Segmentation Enabled)
                // [4] OSF (Operate on Second Packet)
                if((dmaTransmitControl & StartStopTransmission) != 0)
                {
                    this.Log(LogLevel.Debug, "WriteDoubleWord: DMATransmitControl: starting transmission");
                    SendFrames();
                }
                break;
            case Registers.DMAInterruptEnable:
                if(BitHelper.IsBitSet(value, 15)) //normal interrupt summary enable
                {
                    value |= (1u << 11) | (1u << 6) | (1u << 2) | 1u;
                }
                dmaInterruptEnable = value;
                break;
            case Registers.DMAReceiveControl:
                dmaReceiveControl = (value & 0x803F7FFF);
                if(0 == dmaAltReceiveBufferSize)
                {
                    dmaReceiveBufferSize = ((value >> 1) & 0x3FFF);
                    this.Log(LogLevel.Debug, "RBSZ: setting dmaReceiveBufferSize {0} (0x{0:X})", dmaReceiveBufferSize);
                }
                // [31] RPF : DMA RX packet flush
                // [21:16] RXPBL : Receive Programmable Burst Length
                // [0] SR : Start/Stop Receive
                if(0 != (value & StartStopReceive))
                {
                    this.Log(LogLevel.Debug, "DMAReceiveControl:StartStopReceive: start receiving (NOP)");
                }
                break;
            case Registers.DMATransmitRingLength:
                dmaTransmitRingLength = ((value & 0x3FF) + 1);
                dmaTransmitDescriptorEndOfRing = (dmaTransmitDescriptorListAddressBegin + (dmaTransmitRingLength * 16));
                this.Log(LogLevel.Info, "Setting TX ring length {0} dmaTransmitDescriptorEndOfRing 0x{1:X}", dmaTransmitRingLength, dmaTransmitDescriptorEndOfRing);
                break;
            case Registers.DMAReceiveRingLength:
                dmaAltReceiveBufferSize = ((value >> 16) & 0xFF);
                if (dmaAltReceiveBufferSize != 0)
                {
                    dmaReceiveBufferSize = dmaAltReceiveBufferSize;
                    this.Log(LogLevel.Debug, "ARBS: setting dmaReceiveBufferSize {0} (0x{0:X})", dmaReceiveBufferSize);
                }
                dmaReceiveRingLength = ((value & 0x3FF) + 1);
                dmaReceiveDescriptorEndOfRing = (dmaReceiveDescriptorListAddressBegin + (dmaReceiveRingLength * 16));
                this.Log(LogLevel.Info, "Setting RX ring length {0} dmaReceiveDescriptorEndOfRing 0x{1:X}", dmaReceiveRingLength, dmaReceiveDescriptorEndOfRing);
                break;
            case Registers.MTLReceiveQueueOperatingMode:
                mtlReceiveQueueOpMode = ((mtlReceiveQueueOpMode & 0x00700000) | (value & 0x7B));
                // [6] DIS_TCP_EF
                // [5] RSF
                // [4] FEP
                // [3] FUP
                // [1:0] RTC
                break;
            default:
                this.LogUnhandledWrite(offset, value);
                break;
            }
        }

        public void ReceiveFrame(EthernetFrame frame)
        {
            this.Log(LogLevel.Debug, "ReceiveFrame: frame {0}", frame);
            /*if(machine.ElapsedTime < TimeSpan.FromSeconds(30))
            {
                return;
            }*/
            lock(receiveLock)
            {
                // CONSIDER: Should we be checking dmaReceiveControl StartStopReceive state and ignoring packets if ETH_DMACRXCR:SR===0?
                if((dmaStatus & ReceiveStatus) != 0)
                {
                    queue.Enqueue(frame);
                    return;
                }
                if(frame.Bytes.Length < 14)
                {
                    this.Log(LogLevel.Error, "DROPPING - packet too short.");
                    return;
                }
                if(this.machine.IsPaused)
                {
                    this.Log(LogLevel.Debug, "DROPPING - cpu is halted.");
                    return;
                }
                var destinationMac = frame.DestinationMAC;
                // NOTE: We can also check for IsMulticast (01-00-5E) and IsUnicast (which just checks (!IsBroadcast && !IsMulticast)
                // TODO: Though that IsMulticast is currently only IPv4 (EtherType 0800). Since IPv6 multicast is 33-33-xx (EtherType 86DD)
                bool damatch = false;
                if (MAC1_AE && !MAC1_SA)
                {
                    if (0 == MAC1_MBC)
                    {
                        damatch |= destinationMac.Equals(MAC1);
                    }
                    else
                    {
                        // CONSIDER: Since we do not know the software
                        // order of MAC LOW/HIGH writing we cannot
                        // prebuild a mask MACAddress value when
                        // writing the MAC HIGH register; but we could
                        // check for non-zero MACx_MBC when writing
                        // the MAC LOW and update the mask we have in
                        // play. That could allow for some
                        // optimisation of this code since the MAC
                        // address is rarely changed; but we will be
                        // receiving a lot of packets.

                        // MAC1_MBC: b5 = F b4 = E b3 = D b2 = C b1 = B b0 = A
                        this.Log(LogLevel.Debug, "TODO: check MAC1 {0} MBC 0x{1:X}", MAC1, MAC1_MBC);

                        //MAC1.GetByte(0); // A
                        //MAC1.GetByte(1); // B
                        //MAC1.GetByte(2); // C
                        //MAC1.GetByte(3); // D
                        //MAC1.GetByte(4); // E
                        //MAC1.GetByte(5); // F
                    }
                }
                if (MAC2_AE && !MAC2_SA)
                {
                    if (0 == MAC2_MBC)
                    {
                        damatch |= destinationMac.Equals(MAC2);
                    }
                    else
                    {
                        // MAC2_MBC: b5 = F b4 = E b3 = D b2 = C b1 = B b0 = A
                        this.Log(LogLevel.Debug, "TODO: check MAC2 {0} MBC 0x{1:X}", MAC2, MAC2_MBC);
                    }
                }
                if (MAC3_AE && !MAC3_SA)
                {
                    if (0 == MAC3_MBC)
                    {
                        damatch |= destinationMac.Equals(MAC3);
                    }
                    else
                    {
                        // MAC3_MBC: b5 = F b4 = E b3 = D b2 = C b1 = B b0 = A
                        this.Log(LogLevel.Debug, "TODO: check MAC3 {0} MBC 0x{1:X}", MAC3, MAC3_MBC);
                    }
                }
                damatch |= destinationMac.Equals(MAC);
                if(!destinationMac.IsBroadcast && !damatch)
                {
                    this.Log(LogLevel.Debug, "DROPPING - not for us - IsBroadcast {0} destinationMac {1} MAC {2}.", destinationMac.IsBroadcast, destinationMac, MAC);
                    return;
                }
                /*
                if((dmaInterruptEnable & (ReceiveStatus)) == 0)
                {
                    this.Log(LogLevel.Debug, "DROPPING - rx irq is turned off.");
                    return;
                }
                */
                this.Log(LogLevel.Noisy, Misc.DumpPacket(frame, false, machine));
                if(dmaReceiveDescriptorListAddress < 0x20000000)
                {
                    this.Log(LogLevel.Error, "DROPPING - descriptor is not valid. (dmaReceiveDescriptorListAddress 0x{0:X}", dmaReceiveDescriptorListAddress);
                    return;
                }
                var written = 0;
                var first = true;
                var bytes = frame.Bytes;

                if(!EthernetFrame.CheckCRC(bytes))
                {
                    // TODO: ETH_MACCR:CST invalid when Type1 IP checksum engine enabled but is valid when Type2 checksum offload enabled
                    if(!(crcStrippingForTypeFrames && bytes.Length > 1536) || !(automaticPadCRCStripping && bytes.Length < 1536))
                    {
                        this.Log(LogLevel.Info, "DROPPING - Invalid CRC");
                        return;
                    }
                }

                var receiveDescriptor = new RxDescriptor(machine.GetSystemBus(this), this);
                this.Log(LogLevel.Debug, "ReceiveFrame: dmaReceiveDescriptorListAddress 0x{0:X}", dmaReceiveDescriptorListAddress);

                // Should never happen:
                if(0x00000000 == dmaReceiveDescriptorEndOfRing)
                {
                    this.Log(LogLevel.Error, "DROPPING - uninitialised dmaReceiveDescriptorEndOfRing");
                    return;
                }

                receiveDescriptor.Fetch(dmaReceiveDescriptorListAddress);
                if(receiveDescriptor.IsUsed)
                {
                    this.Log(LogLevel.Error, "DROPPING - descriptor is used. dmaReceiveDescriptorListAddress 0x{0:X}", dmaReceiveDescriptorListAddress);
                    return;
                }
                while(!receiveDescriptor.IsUsed)
                {
                    this.Log(LogLevel.Noisy, "DESCRIPTOR ADDR1={0:X}, ADDR2={1:X}", receiveDescriptor.Address1, receiveDescriptor.Address2);
                    if(receiveDescriptor.Address1 < 0x20000000)
                    {
                        this.Log(LogLevel.Error, "Descriptor points outside of ram, aborting... This should not happen!");
                        break;
                    }
                    receiveDescriptor.IsUsed = true;
                    receiveDescriptor.IsFirst = first;
                    first = false;

                    var howManyBytes = Math.Min((int)dmaReceiveBufferSize, (frame.Bytes.Length - written));
                    var toWriteArray = new byte[howManyBytes];

                    if(receiveDescriptor.IsBuffer1Valid)
                    {
                        this.Log(LogLevel.Noisy, "DESCRIPTOR Buffer1={0:X} howManyBytes 0x{1:X}", receiveDescriptor.Buffer1, howManyBytes);
                        Array.Copy(bytes, written, toWriteArray, 0, howManyBytes);
                        machine.GetSystemBus(this).WriteBytes(toWriteArray, receiveDescriptor.Buffer1);
                        written += howManyBytes;
                    }

                    // write second buffer
                    if(frame.Bytes.Length - written > 0)
                    {
                        if(receiveDescriptor.IsBuffer2Valid)
                        {
                            howManyBytes = Math.Min((int)dmaReceiveBufferSize, (frame.Bytes.Length - written));
                            this.Log(LogLevel.Noisy, "DESCRIPTOR Buffer2={0:X} howManyBytes 0x{1:X}", receiveDescriptor.Buffer2, howManyBytes);
                            toWriteArray = new byte[howManyBytes];
                            Array.Copy(bytes, written, toWriteArray, 0, howManyBytes);
                            machine.GetSystemBus(this).WriteBytes(toWriteArray, receiveDescriptor.Address2);
                            written += howManyBytes;
                        }
                    }
                    if((frame.Bytes.Length - written) <= 0)
                    {
                        receiveDescriptor.IsLast = true;
                        receiveDescriptor.ErrorSummary = false;
                        this.NoisyLog("Setting descriptor length to {0}", (uint)frame.Bytes.Length);
                        receiveDescriptor.FrameLength = (uint)frame.Bytes.Length;
                    }

                    this.NoisyLog("Writing descriptor at 0x{0:X}, first={1}, last={2}, written {3} of {4}", dmaReceiveDescriptorListAddress, receiveDescriptor.IsFirst, receiveDescriptor.IsLast, written, frame.Bytes.Length);
                    receiveDescriptor.WriteBack();

                    // STM32H7 normal RDES and TDES are 4-words
                    dmaReceiveDescriptorListAddress += 16;
                    if(dmaReceiveDescriptorEndOfRing == dmaReceiveDescriptorListAddress)
                    {
                        dmaReceiveDescriptorListAddress = dmaReceiveDescriptorListAddressBegin;
                    }
                    this.NoisyLog("dmaReceiveDescriptorListAddress now 0x{0:X}", dmaReceiveDescriptorListAddress);

                    if(frame.Bytes.Length - written <= 0)
                    {
                        dmaStatus |= ReceiveStatus;
                        this.Log(LogLevel.Debug, "ReceiveFrame: dmaStatus now 0x{0:X}", dmaStatus);
                        // Check if RI needs to be raised:
                        if((dmaInterruptEnable & ReceiveStatus) != 0)
                        {
                            this.Log(LogLevel.Debug, "ReceiveFrame: calling IRQ.Set()");
                            IRQ.Set();
                        }
                        else
                        {
                            this.DebugLog("Exiting but not scheduling an interrupt!");
                        }
                        break;
                    }
                    receiveDescriptor.Fetch(dmaReceiveDescriptorListAddress);
                }
                this.DebugLog("Packet of length {0} delivered.", frame.Bytes.Length);
                if(written < frame.Bytes.Length)
                {
                    this.Log(LogLevel.Error, "Delivered only {0} from {1} bytes!", written, frame.Bytes.Length);
                }
            }
        }

        public event Action<EthernetFrame> FrameReady;

        // MAC0 always enabled
        public MACAddress MAC { get; set; }

        public MACAddress MAC1 { get; set; }

        public MACAddress MAC2 { get; set; }

        public MACAddress MAC3 { get; set; }

        public GPIO IRQ { get; private set; }

        public long Size
        {
            get
            {
                return 0x1400;
            }
        }

        private void SendFrames()
        {
            this.Log(LogLevel.Noisy, "Sending frame: dmaTransmitDescriptorListAddress 0x{0:X}", dmaTransmitDescriptorListAddress);
            var transmitDescriptor = new TxDescriptor(machine.GetSystemBus(this), this);
            var packetData = new List<byte>();

            transmitDescriptor.Fetch(dmaTransmitDescriptorListAddress);
            while(!transmitDescriptor.IsUsed)
            {
                // NOTE: When TDES3:LD set then B1L or B2L field should be non-zero
                this.Log(LogLevel.Debug, "SendFrames: FD {0} LD {1}", transmitDescriptor.IsFirst, transmitDescriptor.IsLast);

                transmitDescriptor.IsUsed = true;
                this.Log(LogLevel.Noisy, "Buffer1: READ from {0:X} len={1}", transmitDescriptor.Address1, transmitDescriptor.Buffer1Length);
                packetData.AddRange(machine.GetSystemBus(this).ReadBytes(transmitDescriptor.Address1, transmitDescriptor.Buffer1Length));
//                if(!transmitDescriptor.IsNextDescriptorChained)
                if(0 != transmitDescriptor.Buffer2Length)
                {
                    this.Log(LogLevel.Noisy, "Buffer2: READ from {0:X} len={1}", transmitDescriptor.Address2, transmitDescriptor.Buffer2Length);
                    packetData.AddRange(machine.GetSystemBus(this).ReadBytes(transmitDescriptor.Address2, transmitDescriptor.Buffer2Length));
                }

                transmitDescriptor.WriteBack();

                dmaTransmitDescriptorListAddress += 16;
                if(dmaTransmitDescriptorEndOfRing == dmaTransmitDescriptorListAddress)
                {
                    dmaTransmitDescriptorListAddress = dmaTransmitDescriptorListAddressBegin;
                }
                this.NoisyLog("dmaTransmitDescriptorListAddress now 0x{0:X}", dmaTransmitDescriptorListAddress);

                if(transmitDescriptor.IsLast)
                {
                    this.Log(LogLevel.Noisy, "Sending frame of {0} bytes.", packetData.Count);

                    // NOTE: addCrc: true from github head 20240212
                    if(!Misc.TryCreateFrameOrLogWarning(this, packetData.ToArray(), out var frame, addCrc: true))
                    {
                        continue;
                    }
                    // ChecksumInsertionControl
                    //  0 = checksum insertion disabled
                    //  1 = IP hdr only
                    //  2 = IP hdr and payload
                    //  3 = IP hdr, payload and pseudo-header
                    if(transmitDescriptor.ChecksumInsertionControl > 0)
                    {
                        this.Log(LogLevel.Noisy, "Calculating checksum (mode {0}).", transmitDescriptor.ChecksumInsertionControl);
                        if(transmitDescriptor.ChecksumInsertionControl == 1)
                        {
                            //IP only
                            //frame.FillWithChecksums(supportedEtherChecksums, null);
                            frame.FillWithChecksums(supportedEtherChecksums, new IPProtocolType[] {});
                        }
                        else
                        {
                            //IP and payload
                            frame.FillWithChecksums(supportedEtherChecksums, supportedIPChecksums);
                        }
                    }
                    this.Log(LogLevel.Debug, Misc.DumpPacket(frame, true, machine));

                    // Check if transmit interrupt enabled:
                    if((dmaInterruptEnable & TransmitStatus) != 0)
                    {
                        this.Log(LogLevel.Debug, "SendFrames: Setting dmaStatus TI and IRQ.Set()");
                        // NOTE: RM0468 Rev3 ETH_DMACSR at this point LD marked TDES3 OWN is cleared and packet status updated (written-back to descriptor)
                        dmaStatus |= TransmitStatus;
                        IRQ.Set();
                    }

                    FrameReady?.Invoke(frame);
                    this.Log(LogLevel.Noisy, "Frame sent");
                }
                transmitDescriptor.Fetch(dmaTransmitDescriptorListAddress);
            }
            this.Log(LogLevel.Debug, "SendFrames: end of loop: dmaTransmitDescriptorListAddress 0x{0:x}", dmaTransmitDescriptorListAddress);

            // set TransmitBufferUnavailable when DMA engine entering "Suspended state"
            dmaStatus |= TransmitBufferUnavailableStatus;
            dmaStatus |= TransmitStatus;
            this.Log(LogLevel.Debug, "SendFrames: dmaStatus now 0x{0:X} : dmaInterruptEnable 0x{1:X}", dmaStatus, dmaInterruptEnable);
            if((dmaInterruptEnable & TransmitStatus) != 0)
            {
                this.Log(LogLevel.Debug, "SendFrames: IRQ.Set()");
                IRQ.Set();
            }

            this.Log(LogLevel.Debug, "SendFrames: done");
        }

        private void TryDequeueFrame()
        {
            lock(receiveLock)
            {
                this.Log(LogLevel.Debug, "TryDequeueFrame: queue.Count {0} dmaStatus 0x{1:X}", queue.Count, dmaStatus);
                if((queue.Count > 0) && ((dmaStatus & ReceiveStatus) == 0))
                {
                    var frame = queue.Dequeue();
                    this.Log(LogLevel.Debug, "TryDequeueFrame: calling ReceiveFrame() with dequeued frame {0}", frame);
                    ReceiveFrame(frame);
                }
            }
        }

        private bool MAC1_AE = false;
        private bool MAC1_SA = false;
        private byte MAC1_MBC = 0x00;
        private bool MAC2_AE = false;
        private bool MAC2_SA = false;
        private byte MAC2_MBC = 0x00;
        private bool MAC3_AE = false;
        private bool MAC3_SA = false;
        private byte MAC3_MBC = 0x00;

        private uint macConfiguration;
        private uint macHashTableHigh;
        private uint macHashTableLow;
        private uint macFrameFilter;
        private uint macMiiAddress;
        private ushort macMiiData;

        private uint mtlReceiveQueueOpMode;

        private uint dmaMode;

        private uint dmaReceiveDescriptorListAddress;
        private uint dmaReceiveDescriptorListAddressBegin;
        private uint dmaReceiveDescriptorEndOfRing;
        private uint dmaReceiveTailPointer; // not actually used, but maintained

        private uint dmaTransmitDescriptorListAddress;
        private uint dmaTransmitDescriptorListAddressBegin;
        private uint dmaTransmitDescriptorEndOfRing;
        private uint dmaTransmitTailPointer; // not actually used, but maintained

        private uint dmaStatus;
        private uint dmaInterruptEnable;
        private uint dmaTransmitControl;
        private uint dmaReceiveControl;

        private uint dmaTransmitRingLength;
        private uint dmaReceiveRingLength;

        private uint dmaReceiveBufferSize;
        private uint dmaAltReceiveBufferSize;

        private uint dmaMissedFrameCount; // count of packetrs dropped due to bus error or RPF (flush)
        private bool dmaMissedFrameOverflow;

        private bool automaticPadCRCStripping;
        private bool crcStrippingForTypeFrames;

        private readonly object receiveLock = new object();
        private readonly Queue<EthernetFrame> queue = new Queue<EthernetFrame>();
        private readonly EtherType[] supportedEtherChecksums = { EtherType.IpV4, EtherType.Arp, EtherType.IpV6 };
        private readonly IPProtocolType[] supportedIPChecksums = {
            IPProtocolType.TCP,
            IPProtocolType.UDP,
            IPProtocolType.ICMP,
            IPProtocolType.ICMPV6,
        };

        // DMATransmitControl
        private const uint StartStopTransmission = (1u << 0);

        // DMAReceiveControl
        private const uint StartStopReceive = (1u << 0);

        // DMAStatusRegister and DMAInterruptEnable
        private const uint TransmitStatus = (1u << 0); // TI (Transmit Interrupt)
        private const uint TransmitBufferUnavailableStatus = (1u << 2); // TBU
        private const uint ReceiveStatus = (1u << 6); // RI (Receive Interrupt)
        private const uint NormalInterruptSummary = (1u << 15); // NIS

        private class Descriptor
        {
            public Descriptor(IBusController sysbus, STM32H7_EthernetMAC parent)
            {
                this.sysbus = sysbus;
                this.parent = parent;
            }

            public void Fetch(uint address)
            {
                this.address = address;

                word0 = sysbus.ReadDoubleWord(address);
                word1 = sysbus.ReadDoubleWord(address + 4);
                word2 = sysbus.ReadDoubleWord(address + 8);
                word3 = sysbus.ReadDoubleWord(address + 12);
                parent.Log(LogLevel.Debug, "Desc:Fetch: address 0x{0:X} : 0x{1:X} 0x{2:X} 0x{3:X} 0x{4:X}", address, word0, word1, word2, word3);
            }

            public void WriteBack()
            {
                parent.Log(LogLevel.Debug, "Desc:Write: address 0x{0:X} : 0x{1:X} 0x{2:X} 0x{3:X} 0x{4:X}", address, word0, word1, word2, word3);
                sysbus.WriteDoubleWord(address, word0);
                sysbus.WriteDoubleWord(address + 4, word1);
                sysbus.WriteDoubleWord(address + 8, word2);
                sysbus.WriteDoubleWord(address + 12, word3);
            }

            public bool IsUsed
            {
                get
                {
                    return (word3 & UsedField) == 0;
                }
                set
                {
                    word3 = (word3 & ~UsedField) | (value ? 0u : UsedField);
                    parent.Log(LogLevel.Debug, "Desc:IsUsed: set word3 0x{0:X}", word3);
                }
            }

            public uint Address1
            {
                get{ return word0; }
            }

            public uint Address2
            {
                get{ return word1; }
            }

            protected const uint UsedField = (1u << 31); // [RT]DES3:OWN
            protected uint address;
            protected uint word0;
            protected uint word1;
            protected uint word2;
            protected uint word3;
            private readonly IBusController sysbus;
            private readonly STM32H7_EthernetMAC parent;
        }

        private class TxDescriptor : Descriptor
        {
            public TxDescriptor(IBusController sysbus, STM32H7_EthernetMAC parent) : base(sysbus, parent)
            {
            }

            // RM0468 Rev3 Table581 different than RM0033

            public uint ChecksumInsertionControl
            {
                // If TSE=1 then these bits are upper [17:16] bits of
                // TCP payload length
                get
                {
                    return ((word3 >> 16) & 3);
                }
            }

            public int Buffer1Length
            {
                // CONSIDER: RM0468 Rev3 Table 580 : HL or B1L : depends on TDES3:TSE
                get{ return (int)(word2 & 0x3FFF); }
            }

            public int Buffer2Length
            {
                get{ return (int)((word2 >> 16) & 0x3FFF); }
            }

            public bool IsFirst
            {
                get
                {
                    return (word3 & FirstDescriptor) != 0;
                }
            }

            public bool IsLast
            {
                get
                {
                    return (word3 & LastDescriptor) != 0;
                }
            }

            // TDES0
            //  BUF1AP
            // TDES1
            //  BUF2AP
            // TDES2
            //  IOC  [31]
            //  TTSE [30]
            //  VTIR [15:14]
            // TDES3
            //  OWN  [31]
            //  CTXT [30]
            private const uint FirstDescriptor = (1u << 29);
            private const uint LastDescriptor = (1u << 28);
            //  CPC [27:26]
            //  SAIC [25:23]
            //  THL [22:19]
            //  TSE [18]
            //  CIC/TPL [17:16]
            //  TPL [15]
            //  FL/TPL [14:0]
        }

        private class RxDescriptor : Descriptor
        {
            public RxDescriptor(IBusController sysbus, STM32H7_EthernetMAC parent) : base(sysbus, parent)
            {
            }

            public bool IsBuffer1Valid
            {
                get
                {
                    return ((word3 & Buffer1AddressValid) != 0);
                }
            }

            public bool IsBuffer2Valid
            {
                get
                {
                    return ((word3 & Buffer2AddressValid) != 0);
                }
            }

            public uint Buffer1
            {
                get{ return word0; }
            }

            public uint Buffer2
            {
                get{ return word2; }
            }

            public bool IsLast
            {
                set
                {
                    word3 = ((word3 & ~LastField) | (value ? LastField : 0u));
                }
                get
                {
                    return ((word3 & LastField) != 0);
                }
            }

            public bool IsFirst
            {
                set
                {
                    word3 = ((word3 & ~FirstField) | (value ? FirstField : 0u));
                }
                get
                {
                    return ((word3 & FirstField) != 0);
                }
            }

            public uint FrameLength
            {
                set
                {
                    word3 = ((word3 & ~FrameLengthMask) | (value << FrameLengthShift));
                }
            }

            public bool ErrorSummary
            {
                set
                {
                    word3 = ((word3 & ~ErrorSummaryFlag) | (value ? ErrorSummaryFlag : 0u));
                }
                get
                {
                    return ((word3 & ErrorSummaryFlag) != 0);
                }
            }

            // RDES read
            //
            // RDES0 (read)  BUF1AP     Buffer 1 AddressPointer
            // RDES1 (read)  -          Reserved
            // RDES2 (read)  BUF2AP     Buffer 2 AddressPointer
            // RDES3 (read)  OWN [31]   Descriptor.UsedField
            private const uint InterruptOnCompletion = (1u << 30); // IOC [30]
            private const uint Buffer2AddressValid = (1u << 25); // BUF2V [25]
            private const uint Buffer1AddressValid = (1u << 24); // BUF1V [24]
            //               all other bites reserved

            // RDES writeback
            //
            // RDES0
            //  InnerVLANTag [31:16]
            //  OuterVLANTag [15:0]
            // RDES1
            //  OAM/MAC [31:16] depends on RDES3[18:16]
            //  ExtendedStatus [15:0]
            //   TD [15]
            //   TSA [14]
            //   PV [13]
            //   PFT [12]
            //   PMT [11:8]
            //   IPCE [7]
            //   IPCB [6]
            //   IPV6 [5]
            //   IPV4 [4]
            //   IPHE [3]
            //   PT [2:0] // 0=unknown; 1=UDP, 2=TCP; 3=ICMP, 4=IGMP-if-IPV4
            // RDES2
            //  MACFilterStatus [31:16]
            //   L3L4FM [31:29]
            //   L4FM [28]
            //   L3FM [27]
            //   MADRM [26:19]
            //   HF [18]
            //   DAF [17]
            //   SAF [16]
            //  VF [15]
            //  ARPNR [10]
            // RDES3
            //  OWN [31]   Descriptor.UsedField
            private const uint Context = (1u << 30); // CTXT [30]
            private const uint FirstField = (1u << 29); // FD [29]
            private const uint LastField = (1u << 28); // LD [28]
            //  Status [27:15]
            //   RS2V [27] // RDES2 Status Valid
            //   RS1V [26] // RDES1 Status Valid
            //   RS0V [25] // RDES0 Status Valid
            //   CE [24] // CRC Error
            //   GP [23] // Giant Packet
            //   RWT [22] // Receive Watchdog Timeout
            //   OE [21] // Overflow Error
            //   RE [20] // Receive Error
            //   DE [19] // Dribble Bit Error
            //   LT [18:16] // Length/Type Field
            private const uint ErrorSummaryFlag = (1u << 15); // ES [15] // logical OR of bits 19, 20, 21, 22, 23 and 24 valid when LD set
            private const uint FrameLengthMask = 0x00007FFF; // PL [14:0]
            private const int FrameLengthShift = 0;
        }

        private enum Registers
        {
            MACConfiguration = 0x0000, // ETH_MACCR
            MACFrameFilter = 0x0008, // ETH_MACPFR
            MACHashLow = 0x0010, // ETH_MACHT0R
            MACHashHigh = 0x0014, // ETH_MACHT1R
            MACMIIAddress = 0x0200, // ETH_MACMDIOAR
            MACMIIData = 0x0204, // ETH_MACMDIODR
            MACAddress0High = 0x0300, // ETH_MACA0HR
            MACAddress0Low = 0x0304, // ETH_MACA0LR
            MACAddress1High = 0x0308, // ETH_MACA1HR
            MACAddress1Low = 0x030C, // ETH_MACA1LR
            MACAddress2High = 0x0310, // ETH_MACA2HR
            MACAddress2Low = 0x0314, // ETH_MACA2LR
            MACAddress3High = 0x0318, // ETH_MACA3HR
            MACAddress3Low = 0x031C, // ETH_MACA3LR

            MTLReceiveQueueOperatingMode = 0x0D30, // ETH_MTLRXQOMR

            DMAMode = 0x1000, // ETH_DMAMR
            DMATransmitControl = 0x1104, // ETH_DMACTXCR
            DMAReceiveControl = 0x1108, // ETH_DMACRXCR
            DMATransmitDescriptorListAddress = 0x1114, // ETH_DMACTXDLAR
            DMAReceiveDescriptorListAddress = 0x111C, // ETH_DMACRXDLAR
            DMATransmitTailPointer = 0x1120, // ETH_DMACTXDTPR
            DMAReceiveTailPointer = 0x1128, // ETH_DMACRXDTPR
            DMATransmitRingLength = 0x112C, // ETH_DMACTXRLR
            DMAReceiveRingLength = 0x1130, // ETH_DMACRXRLR
            DMAInterruptEnable = 0x1134, // ETH_DMACIERa
            DMAStatusRegister = 0x1160, // ETH_DMACSR
            DMAMissedFrameCount = 0x116C, // ETH_DMACMFCR
        }
    }
}
