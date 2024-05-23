// Derived from 1.14.0 SynopsysEthernetMAC.cs
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
// Modifications Copyright (c) 2023 eCosCentric Ltd
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
    public sealed class SynopsysEthernetMAC_Fixed : NetworkWithPHY, IDoubleWordPeripheral, IMACInterface, IKnownSize
    {
        public SynopsysEthernetMAC_Fixed(Machine machine) : base(machine)
        {
            MAC = EmulationManager.Instance.CurrentEmulation.MACRepository.GenerateUniqueMAC();
            MAC1 = new MACAddress(0);
            MAC2 = new MACAddress(0);
            MAC3 = new MACAddress(0);
            IRQ = new GPIO();
            Reset();
        }

        public override void Reset()
        {
            macConfiguration = 0x8000;
            macHashTableHigh = 0x0;
            macHashTableLow = 0x0;
            macFrameFilter = 0x0;
            macMiiAddress = 0x0;
            macMiiData = 0x0;
            macFlowControl = 0x0;
            dmaBusMode = 0x20100;
            dmaReceiveDescriptorListAddress = 0x0;
            dmaTransmitDescriptorListAddress = 0x0;
            dmaOperationMode = 0x0;
            dmaInterruptEnable = 0x0;
            // CONSIDER: STM32F207 RM0033 Rev9 shows MACAxHR reset values as 0x0000FFFF and MACAxLR as 0xFFFFFFFF
        }

        public uint ReadDoubleWord(long offset)
        {
            this.NoisyLog("Read from {0}", (Registers)offset);
            switch((Registers)offset)
            {
            case Registers.MACConfiguration:
                return macConfiguration;
            case Registers.MACHashHigh:
                return macHashTableHigh;
            case Registers.MACHashLow:
                return macHashTableLow;
            case Registers.MACFrameFilter:
                return macFrameFilter;
            case Registers.MACMIIAddress:
                return macMiiAddress;
            case Registers.MACMIIData:
                return macMiiData;
            case Registers.MACFlowControl:
                return macFlowControl;
            case Registers.MACAddress0High:
                return (uint)((MAC.F << 8) | MAC.E);
            case Registers.MACAddress0Low:
                return (uint)((MAC.D << 24) | (MAC.C << 16) | (MAC.B << 8) | MAC.A);
            case Registers.MACAddress1High:
                return (uint)((MAC1.F << 8) | MAC1.E);
            case Registers.MACAddress1Low:
                return (uint)((MAC1.D << 24) | (MAC1.C << 16) | (MAC1.B << 8) | MAC1.A);
            case Registers.MACAddress2High:
                return (uint)((MAC2.F << 8) | MAC2.E);
            case Registers.MACAddress2Low:
                return (uint)((MAC2.D << 24) | (MAC2.C << 16) | (MAC2.B << 8) | MAC2.A);
            case Registers.MACAddress3High:
                return (uint)((MAC3.F << 8) | MAC3.E);
            case Registers.MACAddress3Low:
                return (uint)((MAC3.D << 24) | (MAC3.C << 16) | (MAC3.B << 8) | MAC3.A);
            case Registers.DMABusMode:
                return dmaBusMode;
            case Registers.DMAReceiveDescriptorListAddress:
                return dmaReceiveDescriptorListAddress;
            case Registers.DMATransmitDescriptorListAddress:
                return dmaTransmitDescriptorListAddress;
            case Registers.DMAStatusRegister:
                if((dmaStatus & ((1u << 14) | (1u << 6) | (1u << 2) | 1u)) != 0)
                {
                    dmaStatus |= 1u << 16; //Normal interrupt summary
                }
                return dmaStatus;
            case Registers.DMAOperationMode:
                return dmaOperationMode;
            case Registers.DMAInterruptEnable:
                return dmaInterruptEnable;
            default:
                this.LogUnhandledRead(offset);
                return 0;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            this.NoisyLog("Write {0:X} to {1}", value, (Registers)offset);
            switch((Registers)offset)
            {
            case Registers.MACConfiguration:
                macConfiguration = value;
                crcStrippingForTypeFrames = (macConfiguration & 1u << 25) != 0;
                automaticPadCRCStripping = (macConfiguration & 1u << 7) != 0;
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
                var phyId = (value >> 11) & 0x1F;
                var register = (ushort)((value >> 6) & 0x1F);
                var isRead = ((value >> 1) & 0x1) == 0;
                if(!TryGetPhy<ushort>(phyId, out var phy))
                {
                    this.Log(LogLevel.Warning, "Access to unknown phy {0}", phyId);
                    break;
                }
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
                macMiiData = (ushort)value;
                break;
            case Registers.MACFlowControl:
                macFlowControl = value;
                break;
            case Registers.MACAddress0High:
                // NOTE: bit 31 (MO) always HIGH
                MAC = MAC.WithNewOctets(f: (byte)(value >> 8), e: (byte)value);
                break;
            case Registers.MACAddress0Low:
                MAC = MAC.WithNewOctets(d: (byte)(value >> 24), c: (byte)(value >> 16), b: (byte)(value >> 8), a: (byte)value);
                break;
            // CONSIDER: We could optimise with a class to encapsulate the MAC[123] similarity
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
            case Registers.DMABusMode:
                dmaBusMode = value & ~0x1u;
                if((value & 0x1) != 0)
                {
                    Reset();
                }
                break;
            case Registers.DMATransmitPollDemand:
                if((dmaStatus | StartStopTransmission) != 0)
                {
                    SendFrames();
                }
                break;
            case Registers.DMAReceivePollDemand:
                // CONSIDER: Currently a NOP. Real H/W would POLL next RX descriptor at ETH_DMACHRDR
                break;
            case Registers.DMAReceiveDescriptorListAddress:
                this.Log(LogLevel.Info, "Setting RDLA to 0x{0:X}.", value);
                dmaReceiveDescriptorListAddress = value & ~3u;
                dmaReceiveDescriptorListAddressBegin = dmaReceiveDescriptorListAddress;
                break;
            case Registers.DMATransmitDescriptorListAddress:
                this.Log(LogLevel.Info, "Setting TDLA to 0x{0:X}.", value);
                dmaTransmitDescriptorListAddress = value & ~3u;
                //dmaTransmitDescriptorListAddressBegin = dmaReceiveDescriptorListAddress;
                dmaTransmitDescriptorListAddressBegin = dmaTransmitDescriptorListAddress;
                break;
            case Registers.DMAStatusRegister:
                dmaStatus &= ~value; //write 1 to clear;
                if((value & 0x10000) > 0)
                {
                    IRQ.Unset();
                    TryDequeueFrame();
                }
                break;
            case Registers.DMAOperationMode:
                if((value & FlushTransmitFIFO) != 0)
                {
                    this.Log(LogLevel.Warning, "Ignoring ETH_DMAOMR:FTF");
                    value = (value & ~FlushTransmitFIFO);
                }
                dmaOperationMode = value;
                if((value & StartStopTransmission) != 0)
                {
                    SendFrames();
                }
                break;
            case Registers.DMAInterruptEnable:
                if(BitHelper.IsBitSet(value, 16)) //normal interrupt summary enable
                {
                    value |= (1u << 14) | (1u << 6) | (1u << 2) | 1u;
                }
                dmaInterruptEnable = value;
                break;
            default:
                this.LogUnhandledWrite(offset, value);
                break;
            }
        }

        public void ReceiveFrame(EthernetFrame frame)
        {
            /*if(machine.ElapsedTime < TimeSpan.FromSeconds(30))
            {
                return;
            }*/
            lock(receiveLock)
            {
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
                //if(!destinationMac.IsBroadcast && !destinationMac.Equals(MAC))
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
                    if(!(crcStrippingForTypeFrames && bytes.Length > 1536) || !(automaticPadCRCStripping && bytes.Length < 1500))
                    {
                        this.Log(LogLevel.Info, "Invalid CRC, packet discarded");
                        return;
                    }
                }

                var receiveDescriptor = new RxDescriptor(machine.GetSystemBus(this));
                receiveDescriptor.Fetch(dmaReceiveDescriptorListAddress);
                if(receiveDescriptor.IsUsed)
                {
                    this.Log(LogLevel.Error, "DROPPING  - descriptor is used. dmaReceiveDescriptorListAddress 0x{0:X}", dmaReceiveDescriptorListAddress);
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
                    var howManyBytes = Math.Min(receiveDescriptor.Buffer1Length, frame.Bytes.Length - written);
                    var toWriteArray = new byte[howManyBytes];

                    Array.Copy(bytes, written, toWriteArray, 0, howManyBytes);
                    machine.GetSystemBus(this).WriteBytes(toWriteArray, receiveDescriptor.Address1);
                    written += howManyBytes;
                    //write second buffer
                    if(frame.Bytes.Length - written > 0 && !receiveDescriptor.IsNextDescriptorChained)
                    {
                        howManyBytes = Math.Min(receiveDescriptor.Buffer2Length, frame.Bytes.Length - written);
                        toWriteArray = new byte[howManyBytes];
                        Array.Copy(bytes, written, toWriteArray, 0, howManyBytes);
                        machine.GetSystemBus(this).WriteBytes(toWriteArray, receiveDescriptor.Address2);
                        written += howManyBytes;
                    }
                    if(frame.Bytes.Length - written <= 0)
                    {
                        receiveDescriptor.IsLast = true;
                        this.NoisyLog("Setting descriptor length to {0}", (uint)frame.Bytes.Length);
                        receiveDescriptor.FrameLength = (uint)frame.Bytes.Length;
                    }
                    this.NoisyLog("Writing descriptor at 0x{6:X}, first={0}, last={1}, written {2} of {3}. next_chained={4}, endofring={5}", receiveDescriptor.IsFirst, receiveDescriptor.IsLast, written, frame.Bytes.Length, receiveDescriptor.IsNextDescriptorChained, receiveDescriptor.IsEndOfRing, dmaReceiveDescriptorListAddress);
                    receiveDescriptor.WriteBack();
                    // PRM RM0033 Rev9 is specific that RER takes precedence over RCH
                    if(receiveDescriptor.IsEndOfRing)
                    {
                        dmaReceiveDescriptorListAddress = dmaReceiveDescriptorListAddressBegin;
                    } else if(!receiveDescriptor.IsNextDescriptorChained)
                    {
                        //dmaReceiveDescriptorListAddress += 8;
                        dmaReceiveDescriptorListAddress += 16; // STM32F2 normal RDES and TDES are 4-words
                        // Enhanced RX descriptors are 8-words
                    }
                    else
                    {
                        dmaReceiveDescriptorListAddress = receiveDescriptor.Address2;
                    }
                    this.NoisyLog("dmaReceiveDescriptorListAddress now 0x{0:X}", dmaReceiveDescriptorListAddress);
                    if(frame.Bytes.Length - written <= 0)
                    {
                        if((dmaInterruptEnable & (ReceiveStatus)) != 0)// receive interrupt
                        {
                            dmaStatus |= ReceiveStatus;
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

        private bool MAC1_AE = false;
        private bool MAC1_SA = false;
        private byte MAC1_MBC = 0x00;
        public MACAddress MAC1 { get; set; }

        private bool MAC2_AE = false;
        private bool MAC2_SA = false;
        private byte MAC2_MBC = 0x00;
        public MACAddress MAC2 { get; set; }

        private bool MAC3_AE = false;
        private bool MAC3_SA = false;
        private byte MAC3_MBC = 0x00;
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
            this.Log(LogLevel.Noisy, "Sending frame");
            var transmitDescriptor = new TxDescriptor(machine.GetSystemBus(this));
            var packetData = new List<byte>();

            transmitDescriptor.Fetch(dmaTransmitDescriptorListAddress);
            while(!transmitDescriptor.IsUsed)
            {
                transmitDescriptor.IsUsed = true;
                this.Log(LogLevel.Noisy, "GOING TO READ FROM {0:X}, len={1}", transmitDescriptor.Address1, transmitDescriptor.Buffer1Length);
                packetData.AddRange(machine.GetSystemBus(this).ReadBytes(transmitDescriptor.Address1, transmitDescriptor.Buffer1Length));
                if(!transmitDescriptor.IsNextDescriptorChained)
                {
                    packetData.AddRange(machine.GetSystemBus(this).ReadBytes(transmitDescriptor.Address2, transmitDescriptor.Buffer2Length));
                }

                transmitDescriptor.WriteBack();

                if(transmitDescriptor.IsEndOfRing)
                {
                    dmaTransmitDescriptorListAddress = dmaTransmitDescriptorListAddressBegin;
                }
                else if(transmitDescriptor.IsNextDescriptorChained)
                {
                    dmaTransmitDescriptorListAddress = transmitDescriptor.Address2;
                }
                else
                {
                    dmaTransmitDescriptorListAddress += 16;
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
                    if(transmitDescriptor.ChecksumInstertionControl > 0)
                    {
                        this.Log(LogLevel.Noisy, "Calculating checksum (mode {0}).", transmitDescriptor.ChecksumInstertionControl);
                        if(transmitDescriptor.ChecksumInstertionControl == 1)
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

                    if((dmaInterruptEnable & (TransmitStatus)) != 0) // transmit interrupt
                    {
                        dmaStatus |= TransmitStatus;
                        IRQ.Set();
                    }

                    FrameReady?.Invoke(frame);
                }
                transmitDescriptor.Fetch(dmaTransmitDescriptorListAddress);
            }

            //set TransmitBufferUnavailable
            dmaStatus |= TransmitBufferUnavailableStatus;
            dmaStatus |= TransmitStatus;
            if((dmaInterruptEnable & (StartStopTransmission)) == 0)
            {
                IRQ.Set();
            }
            this.Log(LogLevel.Noisy, "Frame sent.");
        }

        private void TryDequeueFrame()
        {
            lock(receiveLock)
            {
                if(queue.Count > 0 && ((dmaStatus & ReceiveStatus) == 0))
                {
                    var frame = queue.Dequeue();
                    ReceiveFrame(frame);
                }
            }
        }

        private bool automaticPadCRCStripping;
        private bool crcStrippingForTypeFrames;
        private uint macConfiguration;
        private uint macHashTableHigh;
        private uint macHashTableLow;
        private uint macFrameFilter;
        private uint macMiiAddress;
        private ushort macMiiData;
        private uint macFlowControl;
        private uint dmaBusMode;
        private uint dmaReceiveDescriptorListAddress;
        private uint dmaReceiveDescriptorListAddressBegin;
        private uint dmaTransmitDescriptorListAddress;
        private uint dmaTransmitDescriptorListAddressBegin;
        private uint dmaStatus;
        private uint dmaOperationMode;
        private uint dmaInterruptEnable;
        private readonly object receiveLock = new object();
        private readonly Queue<EthernetFrame> queue = new Queue<EthernetFrame>();
        private readonly EtherType[] supportedEtherChecksums = { EtherType.IpV4, EtherType.Arp, EtherType.IpV6 };
        private readonly IPProtocolType[] supportedIPChecksums = {
            IPProtocolType.TCP,
            IPProtocolType.UDP,
            IPProtocolType.ICMP,
            IPProtocolType.ICMPV6,
        };
        private const uint StartStopTransmission = 1 << 13;
        private const uint FlushTransmitFIFO = 1 << 20;
        private const uint TransmitBufferUnavailableStatus = 1 << 2;
        private const uint ReceiveStatus = 1 << 6;
        private const uint TransmitStatus = 1 << 0;

        private class Descriptor
        {
            public Descriptor(IBusController sysbus)
            {
                this.sysbus = sysbus;
            }

            public void Fetch(uint address)
            {
                this.address = address;

                word0 = sysbus.ReadDoubleWord(address);
                word1 = sysbus.ReadDoubleWord(address + 4);
                word2 = sysbus.ReadDoubleWord(address + 8);
                word3 = sysbus.ReadDoubleWord(address + 12);
            }

            public void WriteBack()
            {
                sysbus.WriteDoubleWord(address, word0);
                sysbus.WriteDoubleWord(address + 4, word1);
                sysbus.WriteDoubleWord(address + 8, word2);
                sysbus.WriteDoubleWord(address + 12, word3);
            }

            public bool IsUsed
            {
                get
                {
                    return (word0 & UsedField) == 0;
                }
                set
                {
                    word0 = (word0 & ~UsedField) | (value ? 0u : UsedField);
                }
            }

            public uint Address1
            {
                get{ return word2; }
            }

            public uint Address2
            {
                get{ return word3; }
            }

            public int Buffer1Length
            {
                get{ return (int)(word1 & 0x1FFF); }
            }

            public int Buffer2Length
            {
                get{ return (int)((word1 >> 16) & 0x1FFF); }
            }

            protected const uint UsedField = 1u << 31;
            protected uint address;
            protected uint word0;
            protected uint word1;
            protected uint word2;
            protected uint word3;
            private readonly IBusController sysbus;
        }

        private class TxDescriptor : Descriptor
        {
            public TxDescriptor(IBusController sysbus) : base(sysbus)
            {
            }

            public uint ChecksumInstertionControl // sic ChecksumInsertionControl
            {
                get
                {
                    return ((word0 >> 22) & 3);
                }
            }

            public bool IsLast
            {
                get
                {
                    return (word0 & LastField) != 0;
                }
            }

            public bool IsNextDescriptorChained
            {
                get
                {
                    return (word0 & SecondDescriptorChainedField) != 0;
                }
            }

            public bool IsEndOfRing
            {
                get
                {
                    return (word0 & EndOfRingField) != 0;
                }
            }

            private const uint LastField = 1u << 29;
            private const uint SecondDescriptorChainedField = 1u << 20;
            private const uint EndOfRingField = 1u << 21;
        }

        private class RxDescriptor : Descriptor
        {
            public RxDescriptor(IBusController sysbus) : base(sysbus)
            {
            }

            public bool IsNextDescriptorChained
            {
                get
                {
                    return (word1 & SecondDescriptorChainedField) != 0;
                }
            }

            public bool IsEndOfRing
            {
                get
                {
                    return (word1 & EndOfRingField) != 0;
                }
            }

            public bool IsLast
            {
                set
                {
                    word0 = (word0 & ~LastField) | (value ? LastField : 0u);
                }
                get
                {
                    return (word0 & LastField) != 0;
                }
            }

            public bool IsFirst
            {
                set
                {
                    word0 = (word0 & ~FirstField) | (value ? FirstField : 0u);
                }
                get
                {
                    return (word0 & FirstField) != 0;
                }
            }

            public uint FrameLength
            {
                set
                {
                    word0 = (word0 & ~FrameLengthMask) | (value << FrameLengthShift);
                }
            }

            // RDES0
            private const int FrameLengthShift = 16;
            private const uint FrameLengthMask = 0x3FFF0000;
            private const uint LastField = 1u << 8;
            private const uint FirstField = 1u << 9;
            // RDES1
            private const uint EndOfRingField = 1u << 15;
            private const uint SecondDescriptorChainedField = 1u << 14;
        }

        private enum Registers
        {
            MACConfiguration = 0x0000,
            MACFrameFilter = 0x0004,
            MACHashHigh = 0x0008, // ETH_MACHTHR
            MACHashLow = 0x000C, // ETH_MACHTLR
            MACMIIAddress = 0x0010,
            MACMIIData = 0x0014,
            MACFlowControl = 0x0018,
            // ETH_MACVLANTR = 0x001C,
            // ETH_MACRWUFFR = 0x0028,
            // ETH_MACPMTCSR = 0x002C,
            // ETH_MACDBGR = 0x0034,
            // ETH_MACSR = 0x0038,
            // ETH_MACIMR = 0x003C,
            MACAddress0High = 0x0040,
            MACAddress0Low = 0x0044,
            MACAddress1High = 0x0048, // ETH_MACA1HR
            MACAddress1Low = 0x004C, // ETH_MACA1LR
            MACAddress2High = 0x0050, // ETH_MACA2HR
            MACAddress2Low = 0x0054, // ETH_MACA2LR
            MACAddress3High = 0x0058, // ETH_MACA3HR
            MACAddress3Low = 0x005C, // ETH_MACA3LR
            // ETH_MMCCR = 0x0100,
            // ETH_MMCRIR = 0x0104,
            // ETH_MMCTIR = 0x0108,
            // ETH_MMCRIMR = 0x010C,
            // ETH_MMCTIMR = 0x0110,
            // ETH_MMCTGFSCCR = 0x014C
            // ETH_... TODO
            // ETH_PTPPPSCR = 0x072C
            DMABusMode = 0x1000,
            DMATransmitPollDemand = 0x1004,
            DMAReceivePollDemand = 0x1008, // ETH_DMARPDR
            DMAReceiveDescriptorListAddress = 0x100C,
            DMATransmitDescriptorListAddress = 0x1010,
            DMAStatusRegister = 0x1014,
            DMAOperationMode = 0x1018,
            DMAInterruptEnable = 0x101C
            // ETH_DMAMFBOCR = 0x1020,
            // ETH_... TODO
            // ETH_DMACHRBAR = 0x1050
        }
    }
}
