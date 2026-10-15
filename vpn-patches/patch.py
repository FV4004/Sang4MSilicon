from pathlib import Path
import shutil

def apply(dest, patches):
    def change(name, old, new):
        p=dest/'client/easyconnect'/name; s=p.read_text()
        if s.count(old) != 1: raise SystemExit(f'Protocol patch anchor mismatch: {name}')
        p.write_text(s.replace(old,new))
    change('parse.go', 'element := doc.SelectElement("Resource").SelectElement("Rcs")', 'root := doc.SelectElement("Resource")\n\tif root == nil { return ErrMChipSessionExpired }\n\telement := root.SelectElement("Rcs")')
    p=dest/'client/easyconnect/parse.go'; s=p.read_text().replace('rc.SelectAttr("type").Value','rc.SelectAttrValue("type", "")').replace('rc.SelectAttr("proto").Value','rc.SelectAttrValue("proto", "")');p.write_text(s)
    change('client.go', 'log.Printf("Error occurred while parsing resources: %v", err)', 'if errors.Is(err, ErrMChipSessionExpired) { return err }; log.Printf("Error occurred while parsing resources: %v", err)')
    change('client.go', 'time.NewTicker(60 * time.Second)', 'time.NewTicker(20 * time.Second)')
    # Stop cancellation callbacks before clearing the deadline; AfterFunc stop
    # alone does not wait for a callback already running.
    change('client.go', 'stopCancel := context.AfterFunc(ctx, func() {\n\t\t_ = conn.SetDeadline(time.Now())\n\t})\n\treturn func() {\n\t\tstopCancel()\n\t\t_ = conn.SetDeadline(time.Time{})\n\t}, nil', 'completed := make(chan struct{})\n\tstopCancel := context.AfterFunc(ctx, func() {\n\t\tdefer close(completed)\n\t\t_ = conn.SetDeadline(time.Now())\n\t})\n\treturn func() {\n\t\tif !stopCancel() { <-completed }\n\t\t_ = conn.SetDeadline(time.Time{})\n\t}, nil')
    p=dest/'client/easyconnect/protocol.go';s=p.read_text().replace('if reply[0] != 0x01 {','if n < 1 { return nil, io.ErrUnexpectedEOF }\n\tif reply[0] == 0x08 { return nil, ErrSangforShutdown }\n\tif reply[0] == 0x05 || reply[0] == 0x06 || reply[0] == 0x07 || reply[0] == 0x09 { return nil, ErrSangforReconnectLater }\n\tif reply[0] != 0x01 {').replace('switch reply[0] {','if n < 1 { return nil, io.ErrUnexpectedEOF }\n\tswitch reply[0] {');p.write_text(s)
    for name in ['mchip_protocol.go','mchip_protocol_test.go']: shutil.copyfile(patches/name, dest/'client/easyconnect'/name)
