package output

import (

	"encoding/json"  //encoding the report
	"fmt"  //writing to stdout/a file
	"io"  //accepting either stdout or a file as the destination

)

//RenderJSON writes r as indented JSON to w
func RenderJSON(w io.Writer, r Report) error {

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {

		return fmt.Errorf("output: encoding JSON: %w", err)

	}

	_, err = w.Write(append(data, '\n'))
	return err

}
