package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers http.Header
		want    string
		wantErr error
	}{
		{
			name:    "missing authorization header",
			headers: http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header missing key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "malformed header wrong scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "valid api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			want:    "abc123",
			wantErr: nil,
		},
		{
			name: "extra spaces still returns second token",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123 extra"},
			},
			want:    "abc123",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := GetAPIKey(tt.headers)
			if got != tt.want {
				t.Fatalf("GetAPIKey() got = %q, want %q", got, tt.want)
			}

			switch {
			case tt.wantErr == nil && err != nil:
				t.Fatalf("GetAPIKey() err = %v, want nil", err)
			case tt.wantErr != nil && err == nil:
				t.Fatalf("GetAPIKey() err = nil, want %v", tt.wantErr)
			case tt.wantErr != nil && err != nil && err.Error() != tt.wantErr.Error():
				t.Fatalf("GetAPIKey() err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
