package entity

type OONIMeasurementsResponse struct {
	Metadata any                  `json:"metadata"`
	Results  []OONIMeasurementRow `json:"results"`
}
