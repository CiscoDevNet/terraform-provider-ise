// Copyright © 2023 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
//
// Licensed under the Mozilla Public License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mozilla.org/MPL/2.0/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: MPL-2.0

// Code generated by "gen/generator.go"; DO NOT EDIT.

package provider

//template:begin imports
import (
	"context"

	"github.com/CiscoDevNet/terraform-provider-ise/internal/provider/helpers"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

//template:end imports

//template:begin types
type DeviceAdminTimeAndDateCondition struct {
	Id                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	IsNegate           types.Bool   `tfsdk:"is_negate"`
	WeekDays           types.List   `tfsdk:"week_days"`
	WeekDaysException  types.List   `tfsdk:"week_days_exception"`
	StartDate          types.String `tfsdk:"start_date"`
	EndDate            types.String `tfsdk:"end_date"`
	ExceptionStartDate types.String `tfsdk:"exception_start_date"`
	ExceptionEndDate   types.String `tfsdk:"exception_end_date"`
	StartTime          types.String `tfsdk:"start_time"`
	EndTime            types.String `tfsdk:"end_time"`
	ExceptionStartTime types.String `tfsdk:"exception_start_time"`
	ExceptionEndTime   types.String `tfsdk:"exception_end_time"`
}

//template:end types

//template:begin getPath
func (data DeviceAdminTimeAndDateCondition) getPath() string {
	return "/api/v1/policy/device-admin/time-condition"
}

//template:end getPath

//template:begin toBody
func (data DeviceAdminTimeAndDateCondition) toBody(ctx context.Context, state DeviceAdminTimeAndDateCondition) string {
	body := ""
	if !data.Name.IsNull() {
		body, _ = sjson.Set(body, "name", data.Name.ValueString())
	}
	if !data.Description.IsNull() {
		body, _ = sjson.Set(body, "description", data.Description.ValueString())
	}
	body, _ = sjson.Set(body, "conditionType", "TimeAndDateCondition")
	if !data.IsNegate.IsNull() {
		body, _ = sjson.Set(body, "isNegate", data.IsNegate.ValueBool())
	}
	if !data.WeekDays.IsNull() {
		var values []string
		data.WeekDays.ElementsAs(ctx, &values, false)
		body, _ = sjson.Set(body, "weekDays", values)
	}
	if !data.WeekDaysException.IsNull() {
		var values []string
		data.WeekDaysException.ElementsAs(ctx, &values, false)
		body, _ = sjson.Set(body, "weekDaysException", values)
	}
	if !data.StartDate.IsNull() {
		body, _ = sjson.Set(body, "datesRange.startDate", data.StartDate.ValueString())
	}
	if !data.EndDate.IsNull() {
		body, _ = sjson.Set(body, "datesRange.endDate", data.EndDate.ValueString())
	}
	if !data.ExceptionStartDate.IsNull() {
		body, _ = sjson.Set(body, "datesRangeException.startDate", data.ExceptionStartDate.ValueString())
	}
	if !data.ExceptionEndDate.IsNull() {
		body, _ = sjson.Set(body, "datesRangeException.endDate", data.ExceptionEndDate.ValueString())
	}
	if !data.StartTime.IsNull() {
		body, _ = sjson.Set(body, "hoursRange.startTime", data.StartTime.ValueString())
	}
	if !data.EndTime.IsNull() {
		body, _ = sjson.Set(body, "hoursRange.endTime", data.EndTime.ValueString())
	}
	if !data.ExceptionStartTime.IsNull() {
		body, _ = sjson.Set(body, "hoursRangeException.startTime", data.ExceptionStartTime.ValueString())
	}
	if !data.ExceptionEndTime.IsNull() {
		body, _ = sjson.Set(body, "hoursRangeException.endTime", data.ExceptionEndTime.ValueString())
	}
	return body
}

//template:end toBody

//template:begin fromBody
func (data *DeviceAdminTimeAndDateCondition) fromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("response.name"); value.Exists() {
		data.Name = types.StringValue(value.String())
	} else {
		data.Name = types.StringNull()
	}
	if value := res.Get("response.description"); value.Exists() {
		data.Description = types.StringValue(value.String())
	} else {
		data.Description = types.StringNull()
	}
	if value := res.Get("response.isNegate"); value.Exists() {
		data.IsNegate = types.BoolValue(value.Bool())
	} else {
		data.IsNegate = types.BoolNull()
	}
	if value := res.Get("response.weekDays"); value.Exists() {
		data.WeekDays = helpers.GetStringList(value.Array())
	} else {
		data.WeekDays = types.ListNull(types.StringType)
	}
	if value := res.Get("response.weekDaysException"); value.Exists() {
		data.WeekDaysException = helpers.GetStringList(value.Array())
	} else {
		data.WeekDaysException = types.ListNull(types.StringType)
	}
	if value := res.Get("response.datesRange.startDate"); value.Exists() {
		data.StartDate = types.StringValue(value.String())
	} else {
		data.StartDate = types.StringNull()
	}
	if value := res.Get("response.datesRange.endDate"); value.Exists() {
		data.EndDate = types.StringValue(value.String())
	} else {
		data.EndDate = types.StringNull()
	}
	if value := res.Get("response.datesRangeException.startDate"); value.Exists() {
		data.ExceptionStartDate = types.StringValue(value.String())
	} else {
		data.ExceptionStartDate = types.StringNull()
	}
	if value := res.Get("response.datesRangeException.endDate"); value.Exists() {
		data.ExceptionEndDate = types.StringValue(value.String())
	} else {
		data.ExceptionEndDate = types.StringNull()
	}
	if value := res.Get("response.hoursRange.startTime"); value.Exists() {
		data.StartTime = types.StringValue(value.String())
	} else {
		data.StartTime = types.StringNull()
	}
	if value := res.Get("response.hoursRange.endTime"); value.Exists() {
		data.EndTime = types.StringValue(value.String())
	} else {
		data.EndTime = types.StringNull()
	}
	if value := res.Get("response.hoursRangeException.startTime"); value.Exists() {
		data.ExceptionStartTime = types.StringValue(value.String())
	} else {
		data.ExceptionStartTime = types.StringNull()
	}
	if value := res.Get("response.hoursRangeException.endTime"); value.Exists() {
		data.ExceptionEndTime = types.StringValue(value.String())
	} else {
		data.ExceptionEndTime = types.StringNull()
	}
}

//template:end fromBody

//template:begin updateFromBody
func (data *DeviceAdminTimeAndDateCondition) updateFromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("response.name"); value.Exists() && !data.Name.IsNull() {
		data.Name = types.StringValue(value.String())
	} else {
		data.Name = types.StringNull()
	}
	if value := res.Get("response.description"); value.Exists() && !data.Description.IsNull() {
		data.Description = types.StringValue(value.String())
	} else {
		data.Description = types.StringNull()
	}
	if value := res.Get("response.isNegate"); value.Exists() && !data.IsNegate.IsNull() {
		data.IsNegate = types.BoolValue(value.Bool())
	} else {
		data.IsNegate = types.BoolNull()
	}
	if value := res.Get("response.weekDays"); value.Exists() && !data.WeekDays.IsNull() {
		data.WeekDays = helpers.GetStringList(value.Array())
	} else {
		data.WeekDays = types.ListNull(types.StringType)
	}
	if value := res.Get("response.weekDaysException"); value.Exists() && !data.WeekDaysException.IsNull() {
		data.WeekDaysException = helpers.GetStringList(value.Array())
	} else {
		data.WeekDaysException = types.ListNull(types.StringType)
	}
	if value := res.Get("response.datesRange.startDate"); value.Exists() && !data.StartDate.IsNull() {
		data.StartDate = types.StringValue(value.String())
	} else {
		data.StartDate = types.StringNull()
	}
	if value := res.Get("response.datesRange.endDate"); value.Exists() && !data.EndDate.IsNull() {
		data.EndDate = types.StringValue(value.String())
	} else {
		data.EndDate = types.StringNull()
	}
	if value := res.Get("response.datesRangeException.startDate"); value.Exists() && !data.ExceptionStartDate.IsNull() {
		data.ExceptionStartDate = types.StringValue(value.String())
	} else {
		data.ExceptionStartDate = types.StringNull()
	}
	if value := res.Get("response.datesRangeException.endDate"); value.Exists() && !data.ExceptionEndDate.IsNull() {
		data.ExceptionEndDate = types.StringValue(value.String())
	} else {
		data.ExceptionEndDate = types.StringNull()
	}
	if value := res.Get("response.hoursRange.startTime"); value.Exists() && !data.StartTime.IsNull() {
		data.StartTime = types.StringValue(value.String())
	} else {
		data.StartTime = types.StringNull()
	}
	if value := res.Get("response.hoursRange.endTime"); value.Exists() && !data.EndTime.IsNull() {
		data.EndTime = types.StringValue(value.String())
	} else {
		data.EndTime = types.StringNull()
	}
	if value := res.Get("response.hoursRangeException.startTime"); value.Exists() && !data.ExceptionStartTime.IsNull() {
		data.ExceptionStartTime = types.StringValue(value.String())
	} else {
		data.ExceptionStartTime = types.StringNull()
	}
	if value := res.Get("response.hoursRangeException.endTime"); value.Exists() && !data.ExceptionEndTime.IsNull() {
		data.ExceptionEndTime = types.StringValue(value.String())
	} else {
		data.ExceptionEndTime = types.StringNull()
	}
}

//template:end updateFromBody

//template:begin isNull
func (data *DeviceAdminTimeAndDateCondition) isNull(ctx context.Context, res gjson.Result) bool {
	if !data.Name.IsNull() {
		return false
	}
	if !data.Description.IsNull() {
		return false
	}
	if !data.IsNegate.IsNull() {
		return false
	}
	if !data.WeekDays.IsNull() {
		return false
	}
	if !data.WeekDaysException.IsNull() {
		return false
	}
	if !data.StartDate.IsNull() {
		return false
	}
	if !data.EndDate.IsNull() {
		return false
	}
	if !data.ExceptionStartDate.IsNull() {
		return false
	}
	if !data.ExceptionEndDate.IsNull() {
		return false
	}
	if !data.StartTime.IsNull() {
		return false
	}
	if !data.EndTime.IsNull() {
		return false
	}
	if !data.ExceptionStartTime.IsNull() {
		return false
	}
	if !data.ExceptionEndTime.IsNull() {
		return false
	}
	return true
}

//template:end isNull
