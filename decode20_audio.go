package rardecode

type audioVar struct {
	K1, K2, K3, K4, K5 int
	D1, D2, D3, D4     int
	lastDelta          int
	dif                [11]int
	byteCount          int
	lastChar           int
}

type audio20Decoder struct {
	chans     int // number of audio channels
	curChan   int // current audio channel
	chanDelta int

	decoders [4]huffmanDecoder
	vars     [4]audioVar

	br *rarBitReader
}

func (d *audio20Decoder) reset() {
	d.chans = 1
	d.curChan = 0
	d.chanDelta = 0

	for i := range d.vars {
		d.vars[i] = audioVar{}
	}
}

func (d *audio20Decoder) init(br *rarBitReader, table []byte) error {
	d.br = br
	n, err := br.readBits(2)
	if err != nil {
		return err
	}
	d.chans = n + 1
	if d.curChan >= d.chans {
		d.curChan = 0
	}
	table = table[:audioSize*d.chans]
	if err = readCodeLengthTable20(br, table); err != nil {
		return err
	}
	for i := 0; i < d.chans; i++ {
		d.decoders[i].init(table[:audioSize])
		table = table[audioSize:]
	}
	return nil
}

func (d *audio20Decoder) decode(delta int) byte {
	v := &d.vars[d.curChan]
	v.byteCount++
	v.D4 = v.D3
	v.D3 = v.D2
	v.D2 = v.lastDelta - v.D1
	v.D1 = v.lastDelta
	pch := 8*v.lastChar + v.K1*v.D1 + v.K2*v.D2 + v.K3*v.D3 + v.K4*v.D4 + v.K5*d.chanDelta
	pch = (pch >> 3) & 0xFF
	ch := pch - delta
	dd := delta << 3

	v.dif[0] += abs(dd)
	v.dif[1] += abs(dd - v.D1)
	v.dif[2] += abs(dd + v.D1)
	v.dif[3] += abs(dd - v.D2)
	v.dif[4] += abs(dd + v.D2)
	v.dif[5] += abs(dd - v.D3)
	v.dif[6] += abs(dd + v.D3)
	v.dif[7] += abs(dd - v.D4)
	v.dif[8] += abs(dd + v.D4)
	v.dif[9] += abs(dd - d.chanDelta)
	v.dif[10] += abs(dd + d.chanDelta)

	d.chanDelta = ch - v.lastChar
	v.lastDelta = d.chanDelta
	v.lastChar = ch

	if v.byteCount&0x1F == 0 {
		var numMinDif int
		minDif := v.dif[0]
		v.dif[0] = 0
		for i := 1; i < len(v.dif); i++ {
			if v.dif[i] < minDif {
				minDif = v.dif[i]
				numMinDif = i
			}
			v.dif[i] = 0
		}
		switch numMinDif {
		case 1:
			if v.K1 >= -16 {
				v.K1--
			}
		case 2:
			if v.K1 < 16 {
				v.K1++
			}
		case 3:
			if v.K2 >= -16 {
				v.K2--
			}
		case 4:
			if v.K2 < 16 {
				v.K2++
			}
		case 5:
			if v.K3 >= -16 {
				v.K3--
			}
		case 6:
			if v.K3 < 16 {
				v.K3++
			}
		case 7:
			if v.K4 >= -16 {
				v.K4--
			}
		case 8:
			if v.K4 < 16 {
				v.K4++
			}
		case 9:
			if v.K5 >= -16 {
				v.K5--
			}
		case 10:
			if v.K5 < 16 {
				v.K5++
			}
		}
	}
	return byte(ch)
}

func (d *audio20Decoder) fill(dr *decodeReader, size int64) (int64, error) {
	var n int64
	for n < size && dr.notFull() {
		sym, err := d.decoders[d.curChan].readSym(d.br)
		if err != nil {
			return n, err
		}
		if sym == 256 {
			return n, errEndOfBlock
		}
		dr.writeByte(d.decode(sym))
		n++
		d.curChan++
		if d.curChan >= d.chans {
			d.curChan = 0
		}
	}
	return n, nil
}
