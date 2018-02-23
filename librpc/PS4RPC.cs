/* golden */
/* 2/12/2018 */

using System;
using System.Text;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;

namespace librpc
{
    public class PS4RPC
    {
        private Socket sock = null;
        private IPEndPoint enp = null;
        private bool connected = false;
        public bool IsConnected
        {
            get
            {
                return connected;
            }
        }

        private static int RPC_PORT = 733;
        private static uint RPC_PACKET_MAGIC = 0xBDAABBCC;
        private static int RPC_MAX_DATA_LEN = 8192;

        /** commands **/
        private enum RPC_CMDS : uint
        {
            RPC_PROC_READ = 0xBD000001,
            RPC_PROC_WRITE = 0xBD000002,
            RPC_PROC_LIST = 0xBD000003,
            RPC_PROC_INFO = 0xBD000004,
            RPC_PROC_INTALL = 0xBD000005,
            RPC_PROC_CALL = 0xBD000006,
            RPC_PROC_ELF = 0xBD000007,
            RPC_END = 0xBD000008,
            RPC_REBOOT = 0xBD000009,
            RPC_KERN_BASE = 0xBD00000A,
            RPC_KERN_READ = 0xBD00000B,
            RPC_KERN_WRITE = 0xBD00000C
        };

        /** packet sizes **/
        private static int RPC_PACKET_SIZE = 12;
        private static int RPC_PROC_READ_SIZE = 16;
        private static int RPC_PROC_WRITE_SIZE = 16;
        private static int RPC_PROC_LIST_SIZE = 36;
        private static int RPC_PROC_INFO1_SIZE = 4;
        private static int RPC_PROC_INFO2_SIZE = 60;
        private static int RPC_PROC_INSTALL1_SIZE = 4;
        private static int RPC_PROC_INSTALL2_SIZE = 12;
        private static int RPC_PROC_CALL1_SIZE = 68;
        private static int RPC_PROC_CALL2_SIZE = 12;
        private static int RPC_PROC_ELF_SIZE = 8;
        private static int RPC_KERN_BASE_SIZE = 8;
        private static int RPC_KERN_READ_SIZE = 12;
        private static int RPC_KERN_WRITE_SIZE = 12;

        /** status **/
        private enum RPC_STATUS : uint
        {
            RPC_SUCCESS = 0x80000000,
            RPC_TOO_MUCH_DATA = 0xF0000001,
            RPC_READ_ERROR = 0xF0000002,
            RPC_WRITE_ERROR = 0xF0000003,
            RPC_LIST_ERROR = 0xF0000004,
            RPC_INFO_ERROR = 0xF0000005,
            RPC_INFO_NO_MAP = 0x80000006,
            RPC_NO_PROC = 0xF0000007,
            RPC_INSTALL_ERROR = 0xF0000008,
            RPC_CALL_ERROR = 0xF0000009,
            RPC_ELF_ERROR = 0xF000000A,
        };

        /** messages **/
        private static Dictionary<RPC_STATUS, string> StatusMessages = new Dictionary<RPC_STATUS, string>()
        {
            { RPC_STATUS.RPC_SUCCESS, "success"},
            { RPC_STATUS.RPC_TOO_MUCH_DATA, "too much data"},
            { RPC_STATUS.RPC_READ_ERROR, "read error"},
            { RPC_STATUS.RPC_WRITE_ERROR, "write error"},
            { RPC_STATUS.RPC_LIST_ERROR, "process list error"},
            { RPC_STATUS.RPC_INFO_ERROR, "process information error"},
            { RPC_STATUS.RPC_NO_PROC, "no such process error"},
            { RPC_STATUS.RPC_INSTALL_ERROR, "could not install rpc" },
            { RPC_STATUS.RPC_CALL_ERROR, "could not call address" },
            { RPC_STATUS.RPC_ELF_ERROR, "could not map elf" }
        };

        /// <summary>
        /// Initializes PS4RPC class
        /// </summary>
        /// <param name="addr">PlayStation 4 address</param>
        public PS4RPC(IPAddress addr)
        {
            enp = new IPEndPoint(addr, RPC_PORT);
            sock = new Socket(enp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            sock.NoDelay = true;
            sock.ReceiveTimeout = sock.SendTimeout = 5 * 1000;
        }

        /// <summary>
        /// Initializes PS4RPC class
        /// </summary>
        /// <param name="ip">PlayStation 4 ip address</param>
        public PS4RPC(string ip)
        {
            IPAddress addr = null;
            try
            {
                addr = IPAddress.Parse(ip);
            }
            catch (FormatException ex)
            {
                throw ex;
            }

            enp = new IPEndPoint(addr, RPC_PORT);
            sock = new Socket(enp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            sock.NoDelay = true;
            sock.ReceiveTimeout = sock.SendTimeout = 5 * 1000;
        }

        private static string GetNullTermString(byte[] data, int offset)
        {
            int length = Array.IndexOf<byte>(data, 0, offset) - offset;
            if (length < 0)
            {
                length = data.Length - offset;
            }

            return Encoding.ASCII.GetString(data, offset, length);
        }

        private static byte[] SubArray(byte[] data, int offset, int length)
        {
            byte[] bytes = new byte[length];
            Buffer.BlockCopy(data, offset, bytes, 0, length);
            return bytes;
        }

        private static bool IsFatalStatus(RPC_STATUS status)
        {
            // if status first nibble starts with F
            return (uint)status >> 28 == 15;
        }

        /// <summary>
        /// Connects to PlayStation 4
        /// </summary>
        public void Connect()
        {
            if (!connected)
            {
                sock.Connect(enp);
                connected = true;
            }
        }

        /// <summary>
        /// Disconnects from PlayStation 4
        /// </summary>
        public void Disconnect()
        {
            SendCMDPacket(RPC_CMDS.RPC_END, 0);
            sock.Dispose();
            connected = false;
        }

        private void SendPacketData(int length, params object[] fields)
        {
            MemoryStream rs = new MemoryStream();
            foreach (object field in fields)
            {
                byte[] bytes = null;

                // todo: clean up and find better way
                if (field.GetType() == typeof(char))
                {
                    bytes = BitConverter.GetBytes((char)field);
                }
                else if (field.GetType() == typeof(byte))
                {
                    bytes = BitConverter.GetBytes((byte)field);
                }
                else if (field.GetType() == typeof(short))
                {
                    bytes = BitConverter.GetBytes((short)field);
                }
                else if (field.GetType() == typeof(ushort))
                {
                    bytes = BitConverter.GetBytes((ushort)field);
                }
                else if (field.GetType() == typeof(int))
                {
                    bytes = BitConverter.GetBytes((int)field);
                }
                else if (field.GetType() == typeof(uint))
                {
                    bytes = BitConverter.GetBytes((uint)field);
                }
                else if (field.GetType() == typeof(long))
                {
                    bytes = BitConverter.GetBytes((long)field);
                }
                else if (field.GetType() == typeof(ulong))
                {
                    bytes = BitConverter.GetBytes((ulong)field);
                }
                else if (field.GetType() == typeof(byte[]))
                {
                    bytes = (byte[])field;
                }

                rs.Write(bytes, 0, bytes.Length);
            }

            SendData(rs.ToArray(), length);
            rs.Dispose();
        }

        private void SendCMDPacket(RPC_CMDS cmd, int length)
        {
            SendPacketData(RPC_PACKET_SIZE, RPC_PACKET_MAGIC, (uint)cmd, length);
        }

        private RPC_STATUS ReceiveRPCStatus()
        {
            byte[] status = new byte[4];
            sock.Receive(status, 4, SocketFlags.None);
            return (RPC_STATUS)BitConverter.ToUInt32(status, 0);
        }

        private RPC_STATUS CheckRPCStatus()
        {
            RPC_STATUS status = ReceiveRPCStatus();
            if (IsFatalStatus(status))
            {
                string value = "";
                StatusMessages.TryGetValue(status, out value);
                throw new Exception("librpc: " + value);
            }

            return status;
        }

        private void SendData(byte[] data, int length)
        {
            int left = length;
            int offset = 0;
            int sent = 0;
            while (left > 0)
            {
                if (left > RPC_MAX_DATA_LEN)
                {
                    byte[] bytes = SubArray(data, offset, RPC_MAX_DATA_LEN);
                    sent = sock.Send(bytes, RPC_MAX_DATA_LEN, SocketFlags.None);
                    offset += sent;
                    left -= sent;
                }
                else
                {
                    byte[] bytes = SubArray(data, offset, left);
                    sent = sock.Send(bytes, left, SocketFlags.None);
                    offset += sent;
                    left -= sent;
                }
            }
        }

        private byte[] ReceiveData(int length)
        {
            MemoryStream s = new MemoryStream();

            int left = length;
            int recv = 0;
            while (left > 0)
            {
                byte[] b = new byte[RPC_MAX_DATA_LEN];
                recv = sock.Receive(b, RPC_MAX_DATA_LEN, SocketFlags.None);
                s.Write(b, 0, recv);
                left -= recv;
            }

            byte[] data = s.ToArray();

            s.Dispose();

            return data;
        }

        /// <summary>
        /// Read memory
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="address">Memory address</param>
        /// <param name="length">Data length</param>
        /// <returns></returns>
        public byte[] ReadMemory(int pid, ulong address, int length)
        {
            if (!connected)
            {
                throw new Exception("librpc: not connected");
            }

            SendCMDPacket(RPC_CMDS.RPC_PROC_READ, RPC_PROC_READ_SIZE);
            SendPacketData(RPC_PROC_READ_SIZE, pid, address, length);
            CheckRPCStatus();
            return ReceiveData(length);
        }

        /// <summary>
        /// Write memory
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="address">Memory address</param>
        /// <param name="data">Data</param>
        public void WriteMemory(int pid, ulong address, byte[] data)
        {
            if (!connected)
            {
                throw new Exception("librpc: not connected");
            }

            if (data.Length > RPC_MAX_DATA_LEN)
            {
                // write RPC_MAX_DATA_LEN
                byte[] nowdata = SubArray(data, 0, RPC_MAX_DATA_LEN);

                SendCMDPacket(RPC_CMDS.RPC_PROC_WRITE, RPC_PROC_WRITE_SIZE);
                SendPacketData(RPC_PROC_WRITE_SIZE, pid, address, RPC_MAX_DATA_LEN);
                CheckRPCStatus();
                SendData(nowdata, RPC_MAX_DATA_LEN);
                CheckRPCStatus();

                // call WriteMemory again with rest of it
                int nextlength = data.Length - RPC_MAX_DATA_LEN;
                ulong nextaddr = address + (ulong)RPC_MAX_DATA_LEN;
                byte[] nextdata = SubArray(data, RPC_MAX_DATA_LEN, nextlength);
                WriteMemory(pid, nextaddr, nextdata);
            }
            else if (data.Length > 0)
            {
                SendCMDPacket(RPC_CMDS.RPC_PROC_WRITE, RPC_PROC_WRITE_SIZE);
                SendPacketData(RPC_PROC_WRITE_SIZE, pid, address, data.Length);
                CheckRPCStatus();
                SendData(data, data.Length);
                CheckRPCStatus();
            }
        }

        /// <summary>
        /// Get kernel base address
        /// </summary>
        /// <returns></returns>
        public ulong KernelBase()
        {
            if (!connected)
            {
                throw new Exception("librpc: not connected");
            }

            SendCMDPacket(RPC_CMDS.RPC_KERN_BASE, 0);
            CheckRPCStatus();
            return BitConverter.ToUInt64(ReceiveData(RPC_KERN_BASE_SIZE), 0);

        }

        /// <summary>
        /// Read memory from kernel
        /// </summary>
        /// <param name="address">Memory address</param>
        /// <param name="length">Data length</param>
        /// <returns></returns>
        public byte[] KernelReadMemory(ulong address, int length)
        {
            if (!connected)
            {
                throw new Exception("librpc: not connected");
            }

            SendCMDPacket(RPC_CMDS.RPC_KERN_READ, RPC_KERN_READ_SIZE);
            SendPacketData(RPC_KERN_READ_SIZE, address, length);
            CheckRPCStatus();
            return ReceiveData(length);
        }

        /// <summary>
        /// Write memory in kernel
        /// </summary>
        /// <param name="address">Memory address</param>
        /// <param name="data">Data</param>
        public void KernelWriteMemory(ulong address, byte[] data)
        {
            if (!connected)
            {
                throw new Exception("librpc: not connected");
            }

            if (data.Length > RPC_MAX_DATA_LEN)
            {
                // write RPC_MAX_DATA_LEN
                byte[] nowdata = SubArray(data, 0, RPC_MAX_DATA_LEN);

                SendCMDPacket(RPC_CMDS.RPC_KERN_WRITE, RPC_KERN_WRITE_SIZE);
                SendPacketData(RPC_KERN_WRITE_SIZE, address, RPC_MAX_DATA_LEN);
                CheckRPCStatus();
                SendData(nowdata, RPC_MAX_DATA_LEN);
                CheckRPCStatus();

                // call WriteMemory again with rest of it
                int nextlength = data.Length - RPC_MAX_DATA_LEN;
                ulong nextaddr = address + (ulong)RPC_MAX_DATA_LEN;
                byte[] nextdata = SubArray(data, RPC_MAX_DATA_LEN, nextlength);
                KernelWriteMemory(nextaddr, nextdata);
            }
            else if (data.Length > 0)
            {
                SendCMDPacket(RPC_CMDS.RPC_KERN_WRITE, RPC_KERN_WRITE_SIZE);
                SendPacketData(RPC_KERN_WRITE_SIZE, address, data.Length);
                CheckRPCStatus();
                SendData(data, data.Length);
                CheckRPCStatus();
            }
        }

        /// <summary>
        /// Get current process list
        /// </summary>
        /// <returns></returns>
        public ProcessList GetProcessList()
        {
            if (!connected)
            {
                throw new Exception("librpc: not connected");
            }

            SendCMDPacket(RPC_CMDS.RPC_PROC_LIST, 0);
            CheckRPCStatus();

            // recv count
            byte[] bnumber = new byte[4];
            sock.Receive(bnumber, 4, SocketFlags.None);
            int number = BitConverter.ToInt32(bnumber, 0);

            // recv data
            byte[] data = ReceiveData(number * RPC_PROC_LIST_SIZE);

            // parse data
            string[] procnames = new string[number];
            int[] pids = new int[number];
            for (int i = 0; i < number; i++)
            {
                int offset = i * RPC_PROC_LIST_SIZE;
                procnames[i] = GetNullTermString(data, offset);
                pids[i] = BitConverter.ToInt32(data, offset + 32);
            }

            return new ProcessList(number, procnames, pids);
        }

        /// <summary>
        /// Get process information (memory map)
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <returns></returns>
        public ProcessInfo GetProcessInfo(int pid)
        {
            if (!connected)
            {
                throw new Exception("librpc: not connected");
            }

            SendCMDPacket(RPC_CMDS.RPC_PROC_INFO, RPC_PROC_INFO1_SIZE);
            SendPacketData(RPC_PROC_INFO1_SIZE, pid);

            RPC_STATUS status = CheckRPCStatus();
            if (status == RPC_STATUS.RPC_INFO_NO_MAP)
            {
                return new ProcessInfo(pid, null);
            }

            // recv count
            byte[] bnumber = new byte[4];
            sock.Receive(bnumber, 4, SocketFlags.None);
            int number = BitConverter.ToInt32(bnumber, 0);

            // recv data
            byte[] data = ReceiveData(number * RPC_PROC_INFO2_SIZE);

            // parse data
            MemoryEntry[] entries = new MemoryEntry[number];
            for (int i = 0; i < number; i++)
            {
                int offset = i * RPC_PROC_INFO2_SIZE;
                entries[i] = new MemoryEntry();

                entries[i].name = GetNullTermString(data, offset);
                entries[i].start = BitConverter.ToUInt64(data, offset + 32);
                entries[i].end = BitConverter.ToUInt64(data, offset + 40);
                entries[i].offset = BitConverter.ToUInt64(data, offset + 48);
                entries[i].prot = BitConverter.ToUInt32(data, offset + 56);
            }

            return new ProcessInfo(pid, entries);
        }

        /// <summary>
        /// Install RPC into a process, this returns a stub address that you should pass into call functions
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <returns></returns>
        public ulong InstallRPC(int pid)
        {
            if (!connected)
            {
                throw new Exception("librpc: not connected");
            }

            SendCMDPacket(RPC_CMDS.RPC_PROC_INTALL, RPC_PROC_INSTALL1_SIZE);
            SendPacketData(RPC_PROC_INSTALL1_SIZE, pid);
            CheckRPCStatus();
            byte[] data = ReceiveData(RPC_PROC_INSTALL2_SIZE);
            return BitConverter.ToUInt64(data, 4);
        }

        /// <summary>
        /// Call function (returns rax)
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="rpcstub">Stub address from InstallRPC</param>
        /// <param name="address">Address to call</param>
        /// <param name="args">Arguments array</param>
        /// <returns></returns>
        public ulong Call(int pid, ulong rpcstub, ulong address, params object[] args)
        {
            if (!connected)
            {
                throw new Exception("librpc: not connected");
            }

            SendCMDPacket(RPC_CMDS.RPC_PROC_CALL, RPC_PROC_CALL1_SIZE);

            MemoryStream rs = new MemoryStream();
            rs.Write(BitConverter.GetBytes(pid), 0, sizeof(int));
            rs.Write(BitConverter.GetBytes(rpcstub), 0, sizeof(ulong));
            rs.Write(BitConverter.GetBytes(address), 0, sizeof(ulong));

            int num = 0;
            foreach (object arg in args)
            {
                byte[] bytes = new byte[8];

                if (arg.GetType() == typeof(char))
                {
                    byte[] tmp = BitConverter.GetBytes((char)arg);
                    Buffer.BlockCopy(tmp, 0, bytes, 0, sizeof(char));

                    byte[] pad = new byte[sizeof(ulong) - sizeof(char)];
                    Buffer.BlockCopy(pad, 0, bytes, sizeof(char), pad.Length);
                }
                else if (arg.GetType() == typeof(byte))
                {
                    byte[] tmp = BitConverter.GetBytes((byte)arg);
                    Buffer.BlockCopy(tmp, 0, bytes, 0, sizeof(byte));

                    byte[] pad = new byte[sizeof(ulong) - sizeof(byte)];
                    Buffer.BlockCopy(pad, 0, bytes, sizeof(byte), pad.Length);
                }
                else if (arg.GetType() == typeof(short))
                {
                    byte[] tmp = BitConverter.GetBytes((short)arg);
                    Buffer.BlockCopy(tmp, 0, bytes, 0, sizeof(short));

                    byte[] pad = new byte[sizeof(ulong) - sizeof(short)];
                    Buffer.BlockCopy(pad, 0, bytes, sizeof(short), pad.Length);
                }
                else if (arg.GetType() == typeof(ushort))
                {
                    byte[] tmp = BitConverter.GetBytes((ushort)arg);
                    Buffer.BlockCopy(tmp, 0, bytes, 0, sizeof(ushort));

                    byte[] pad = new byte[sizeof(ulong) - sizeof(ushort)];
                    Buffer.BlockCopy(pad, 0, bytes, sizeof(ushort), pad.Length);
                }
                else if (arg.GetType() == typeof(int))
                {
                    byte[] tmp = BitConverter.GetBytes((int)arg);
                    Buffer.BlockCopy(tmp, 0, bytes, 0, sizeof(int));

                    byte[] pad = new byte[sizeof(ulong) - sizeof(int)];
                    Buffer.BlockCopy(pad, 0, bytes, sizeof(int), pad.Length);
                }
                else if (arg.GetType() == typeof(uint))
                {
                    byte[] tmp = BitConverter.GetBytes((uint)arg);
                    Buffer.BlockCopy(tmp, 0, bytes, 0, sizeof(uint));

                    byte[] pad = new byte[sizeof(ulong) - sizeof(uint)];
                    Buffer.BlockCopy(pad, 0, bytes, sizeof(uint), pad.Length);
                }
                else if (arg.GetType() == typeof(long))
                {
                    byte[] tmp = BitConverter.GetBytes((long)arg);
                    Buffer.BlockCopy(tmp, 0, bytes, 0, sizeof(long));
                }
                else if (arg.GetType() == typeof(ulong))
                {
                    byte[] tmp = BitConverter.GetBytes((ulong)arg);
                    Buffer.BlockCopy(tmp, 0, bytes, 0, sizeof(ulong));
                }

                rs.Write(bytes, 0, bytes.Length);
                num++;
            }

            if (num > 6)
            {
                throw new Exception("librpc: too many call arguments");
            }
            else if (num < 6)
            {
                for (int i = 0; i < (6 - num); i++)
                {
                    rs.Write(BitConverter.GetBytes((ulong)0), 0, sizeof(ulong));
                }
            }

            SendData(rs.ToArray(), RPC_PROC_CALL1_SIZE);
            rs.Dispose();

            CheckRPCStatus();

            byte[] data = ReceiveData(RPC_PROC_CALL2_SIZE);
            return BitConverter.ToUInt64(data, 4);
        }

        /// <summary>
        /// Load an elf into a process
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="elf">Elf bytes</param>
        public void LoadElf(int pid, byte[] elf)
        {
            SendCMDPacket(RPC_CMDS.RPC_PROC_ELF, RPC_PROC_ELF_SIZE);
            SendPacketData(RPC_PROC_ELF_SIZE, pid, elf.Length);
            SendData(elf, elf.Length);
            CheckRPCStatus();
        }

        /// <summary>
        /// Load an elf into a process
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="filename">Elf file path</param>
        public void LoadElf(int pid, string filename)
        {
            LoadElf(pid, File.ReadAllBytes(filename));
        }

        /// <summary>
        /// Reboot console
        /// </summary>
        public void Reboot()
        {
            if (!connected)
            {
                throw new Exception("librpc: not connected");
            }

            SendCMDPacket(RPC_CMDS.RPC_REBOOT, 0);
            sock.Dispose();
            connected = false;
        }

        /** read wrappers **/
        public Byte ReadByte(int pid, ulong address)
        {
            return ReadMemory(pid, address, sizeof(Byte))[0];
        }
        public Char ReadChar(int pid, ulong address)
        {
            return BitConverter.ToChar(ReadMemory(pid, address, sizeof(Char)), 0);
        }
        public Int16 ReadInt16(int pid, ulong address)
        {
            return BitConverter.ToInt16(ReadMemory(pid, address, sizeof(Int16)), 0);
        }
        public UInt16 ReadUInt16(int pid, ulong address)
        {
            return BitConverter.ToUInt16(ReadMemory(pid, address, sizeof(UInt16)), 0);
        }
        public Int32 ReadInt32(int pid, ulong address)
        {
            return BitConverter.ToInt32(ReadMemory(pid, address, sizeof(Int32)), 0);
        }
        public UInt32 ReadUInt32(int pid, ulong address)
        {
            return BitConverter.ToUInt32(ReadMemory(pid, address, sizeof(UInt32)), 0);
        }
        public Int64 ReadInt64(int pid, ulong address)
        {
            return BitConverter.ToInt64(ReadMemory(pid, address, sizeof(Int64)), 0);
        }
        public UInt64 ReadUInt64(int pid, ulong address)
        {
            return BitConverter.ToUInt64(ReadMemory(pid, address, sizeof(UInt64)), 0);
        }

        /** write wrappers **/
        public void WriteByte(int pid, ulong address, Byte value)
        {
            WriteMemory(pid, address, new byte[] { value });
        }
        public void WriteChar(int pid, ulong address, Char value)
        {
            WriteMemory(pid, address, BitConverter.GetBytes(value));
        }
        public void WriteInt16(int pid, ulong address, Int16 value)
        {
            WriteMemory(pid, address, BitConverter.GetBytes(value));
        }
        public void WriteUInt16(int pid, ulong address, UInt16 value)
        {
            WriteMemory(pid, address, BitConverter.GetBytes(value));
        }
        public void WriteInt32(int pid, ulong address, Int32 value)
        {
            WriteMemory(pid, address, BitConverter.GetBytes(value));
        }
        public void WriteUInt32(int pid, ulong address, UInt32 value)
        {
            WriteMemory(pid, address, BitConverter.GetBytes(value));
        }
        public void WriteInt64(int pid, ulong address, Int64 value)
        {
            WriteMemory(pid, address, BitConverter.GetBytes(value));
        }
        public void WriteUInt64(int pid, ulong address, UInt64 value)
        {
            WriteMemory(pid, address, BitConverter.GetBytes(value));
        }

        /* float/double */
        public float ReadSingle(int pid, ulong address)
        {
            return BitConverter.ToSingle(ReadMemory(pid, address, sizeof(float)), 0);
        }
        public void WriteSingle(int pid, ulong address, float value)
        {
            WriteMemory(pid, address, BitConverter.GetBytes(value));
        }
        public double ReadDouble(int pid, ulong address)
        {
            return BitConverter.ToDouble(ReadMemory(pid, address, sizeof(double)), 0);
        }
        public void WriteDouble(int pid, ulong address, double value)
        {
            WriteMemory(pid, address, BitConverter.GetBytes(value));
        }

        /* string */
        public string ReadString(int pid, ulong address)
        {
            string str = "";
            ulong i = 0;

            while (true)
            {
                byte value = ReadByte(pid, address + i);
                if(value == 0)
                {
                    break;
                }

                str += Convert.ToChar(value);
                i++;
            }

            return str;
        }
        public void WriteString(int pid, ulong address, string str)
        {
            WriteMemory(pid, address, Encoding.ASCII.GetBytes(str));
            WriteByte(pid, address + (ulong)str.Length, 0);
        }
    }
}
