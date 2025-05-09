//
// garbler.go
//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

// FileSize specifies a file (or data transfer) size in bytes.
type FileSize uint64

func (s FileSize) String() string {
	if s > 1000*1000*1000*1000 {
		return fmt.Sprintf("%dTB", s/(1000*1000*1000*1000))
	} else if s > 1000*1000*1000 {
		return fmt.Sprintf("%dGB", s/(1000*1000*1000))
	} else if s > 1000*1000 {
		return fmt.Sprintf("%dMB", s/(1000*1000))
	} else if s > 1000 {
		return fmt.Sprintf("%dkB", s/1000)
	} else {
		return fmt.Sprintf("%dB", s)
	}
}

// Garbler runs the garbler on the P2P network.
func Garbler(conn *p2p.Conn, oti ot.OT, circ *Circuit, inputs *big.Int,
	verbose bool) ([]*big.Int, error) {

	timing := NewTiming()
	if verbose {
		fmt.Printf(" - Garbling...\n")
	}

	var key [32]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return nil, err
	}

	garbled, err := circ.Garble(key[:])
	if err != nil {
		return nil, err
	}

	timing.Sample("Garble", nil)

	// Send program info.
	if verbose {
		fmt.Println("-- circuit has been garbled --")
		// get output wires:
		for i := 0; i < circ.Outputs.Size(); i++ {
			wire := garbled.Wires[circ.NumWires-circ.Outputs.Size()+i]
			fmt.Println("out wire: ", i, ", L0: ", wire.L0.String(), ", L1: ", wire.L1.String())
			// fmt.Println("check wire label L1:", garbled.Wires[len(garbled.Wires)-1].L1)
		}
		fmt.Printf(" - Sending garbled circuit...\n")
	}
	if err := conn.SendData(key[:]); err != nil {
		return nil, err
	}

	// Send garbled tables.
	if err := conn.SendUint32(len(garbled.Gates)); err != nil {
		return nil, err
	}
	var labelData ot.LabelData
	for _, data := range garbled.Gates {
		if err := conn.SendUint32(len(data)); err != nil {
			return nil, err
		}
		for _, d := range data {
			if err := conn.SendLabel(d, &labelData); err != nil {
				return nil, err
			}
		}
	}

	// Select our inputs.
	var n1 []ot.Label
	for i := 0; i < circ.Inputs[0].Size; i++ {
		wire := garbled.Wires[i]

		var n ot.Label

		if inputs.Bit(i) == 1 {
			n = wire.L1
		} else {
			n = wire.L0
		}
		n1 = append(n1, n)
	}

	// Send our inputs.
	for idx, i := range n1 {
		if verbose && false {
			fmt.Printf("N1[%d]:\t%s\n", idx, i)
		}
		if err := conn.SendLabel(i, &labelData); err != nil {
			return nil, err
		}
	}
	ioStats := conn.Stats.Sum()
	timing.Sample("Xfer", []string{FileSize(ioStats).String()})
	if verbose {
		fmt.Printf(" - Processing messages...\n")
	}

	// Init oblivious transfer.
	err = oti.InitSender(conn)
	if err != nil {
		return nil, err
	}
	xfer := conn.Stats.Sum() - ioStats
	ioStats = conn.Stats.Sum()
	timing.Sample("OT Init", []string{FileSize(xfer).String()})

	// Peer OTs its inputs.
	offset, err := conn.ReceiveUint32()
	if err != nil {
		return nil, err
	}
	count, err := conn.ReceiveUint32()
	if err != nil {
		return nil, err
	}
	if offset != circ.Inputs[0].Size || count != circ.Inputs[1].Size {
		return nil, fmt.Errorf("peer can't OT wires [%d...%d[",
			offset, offset+count)
	}
	err = oti.Send(garbled.Wires[offset : offset+count])
	if err != nil {
		return nil, err
	}
	xfer = conn.Stats.Sum() - ioStats
	ioStats = conn.Stats.Sum()
	timing.Sample("OT", []string{FileSize(xfer).String()})

	// Resolve result values.

	result := big.NewInt(0)
	var label ot.Label

	fmt.Println("circ output sitze:", circ.Outputs.Size())
	for i := 0; i < circ.Outputs.Size(); i++ {
		err := conn.ReceiveLabel(&label, &labelData)
		if err != nil {
			return nil, err
		}
		fmt.Println("got label data:", labelData, hex.EncodeToString(labelData[:]))
		fmt.Println("got label:", label)

		if i == 0 {
			timing.Sample("Eval", nil)
		}
		wire := garbled.Wires[circ.NumWires-circ.Outputs.Size()+i]

		// decoding...
		var bit uint
		if label.Equal(wire.L0) {
			bit = 0
		} else if label.Equal(wire.L1) {
			bit = 1
		} else {
			return nil, fmt.Errorf("unknown label %s for result %d", label, i)
		}
		fmt.Println("bit resolution yields:", bit)
		result = big.NewInt(0).SetBit(result, i, bit)
	}
	data := result.Bytes()
	if err := conn.SendData(data); err != nil {
		return nil, err
	}
	if err := conn.Flush(); err != nil {
		return nil, err
	}

	xfer = conn.Stats.Sum() - ioStats
	timing.Sample("Result", []string{FileSize(xfer).String()})
	if verbose {
		timing.Print(conn.Stats)
	}

	return circ.Outputs.Split(result), nil
}
