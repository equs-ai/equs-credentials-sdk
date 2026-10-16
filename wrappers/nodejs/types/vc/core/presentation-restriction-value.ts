import { InternalPresentationRestrictionValue, PresentationRestrictionValueType } from "../../..";

export class PresentationRestrictionValue {
  /**
    This should be used when the filtering value must be equal to the given string
   */
  static withString(s: string): InternalPresentationRestrictionValue {
    return {
      type: PresentationRestrictionValueType.String,
      string: s,
    };
  }
  /**
   This should be used when the filtering value must match the given pattern
   */
  static withPattern(s: string): InternalPresentationRestrictionValue {
    return {
      type: PresentationRestrictionValueType.Pattern,
      string: s,
    };
  }
  /**
   This should be used when the filtering values must contain all the strings of one of inner arrays
   */
  static withArray(a: Array<Array<string>>): InternalPresentationRestrictionValue {
    return {
      type: PresentationRestrictionValueType.Array,
      array: a,
    };
  }
}
